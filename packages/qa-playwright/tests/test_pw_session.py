# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Sessions: a fresh isolated context each, nothing shared, verifiable cleanup, a lost session is a typed error."""
import dataclasses

import pytest
from agent_harness.qa.errors import (RedactionFailed, SessionLost, UnsupportedOperation)
from agent_harness.qa.records import (ActionKind, ResetScope, SessionHandle, SessionProfile)
from qa_playwright import ContextSpec

from qa_pw_support import (APP, PROFILE_ID, desc, locate_one, login_page, make_world, request)


def test_every_session_gets_its_own_fresh_context_spec():
    w = make_world(login_page())
    a, b = w.open(), w.open()
    assert a != b
    assert [s.session_id for s in w.driver.specs] == [a.session_id, b.session_id]
    assert w.driver.sessions[a.session_id] is not w.driver.sessions[b.session_id]


def test_a_context_spec_has_no_field_that_could_carry_stored_state():
    names = {f.name for f in dataclasses.fields(ContextSpec)}
    assert not {n for n in names if any(x in n for x in ("storage", "state", "profile_dir", "user_data", "cookies", "persistent"))} - {"profile_id"}


def test_the_context_is_built_locked_down():
    w = make_world(login_page())
    w.open()
    spec = w.driver.specs[0]
    assert (spec.accept_downloads, spec.allow_popups, spec.allow_file_choosers) == (False, False, False)
    assert spec.service_workers == "block" and spec.permissions == () and spec.record_trace is False
    assert spec.request_gate is not None


def test_session_flags_from_the_profile_are_passed_through_not_assumed():
    w = make_world(login_page())
    w.open(allow_downloads=True, allow_popups=True, allow_file_choosers=True)
    spec = w.driver.specs[0]
    assert (spec.accept_downloads, spec.allow_popups, spec.allow_file_choosers) == (True, True, True)


def test_storage_set_in_one_session_is_not_visible_in_the_next():
    w = make_world(login_page())
    a = w.open()
    first = w.driver.sessions[a.session_id]
    first.local_storage["k"] = "v"
    first.cookies["c"] = "1"
    w.adapter.close_session(a)
    b = w.open()
    second = w.driver.sessions[b.session_id]
    assert second.local_storage == {} and second.cookies == {}


def test_reset_context_clears_storage_logs_and_candidates_and_returns_to_a_blank_page():
    w = make_world(login_page())
    h = w.open()
    w.adapter.act(h, request(ActionKind.NAVIGATE, value=f"{APP}/login"), None)
    sess = w.driver.sessions[h.session_id]
    sess.local_storage["k"] = "v"
    target = locate_one(w, h, desc("button", "Submit"))
    result = w.adapter.reset(h, ResetScope.CONTEXT)
    assert result.ok and result.scope is ResetScope.CONTEXT
    assert sess.local_storage == {} and sess.page.url == "about:blank"
    with pytest.raises(Exception) as err:
        w.adapter.act(h, request(ActionKind.CLICK), target)          # the candidate belonged to the old context
    assert err.value.code == "LOCATOR_NOT_FOUND"


def test_reset_of_fixture_or_environment_needs_a_resetter_and_runs_it_after_the_context_reset():
    w = make_world(login_page())
    h = w.open()
    with pytest.raises(UnsupportedOperation):
        w.adapter.reset(h, ResetScope.FIXTURE)
    seen = []
    w2 = make_world(login_page(), fixture_resetter=lambda scope: seen.append(scope) or True)
    h2 = w2.open()
    assert w2.adapter.reset(h2, ResetScope.FIXTURE).scope is ResetScope.FIXTURE
    assert seen == ["FIXTURE"]


@pytest.mark.parametrize("resetter", [lambda scope: False, lambda scope: None, lambda scope: 1 / 0])
def test_a_resetter_that_fails_or_answers_oddly_is_reset_failed(resetter):
    w = make_world(login_page(), fixture_resetter=resetter)
    h = w.open()
    with pytest.raises(Exception) as err:
        w.adapter.reset(h, ResetScope.ENVIRONMENT)
    assert err.value.code == "RESET_FAILED"


def test_a_context_that_cannot_be_reset_is_reset_failed_and_the_session_is_then_unusable():
    w = make_world(login_page())
    h = w.open()
    w.driver.fail_reset = True
    with pytest.raises(Exception) as err:
        w.adapter.reset(h, ResetScope.CONTEXT)
    assert err.value.code == "RESET_FAILED"
    with pytest.raises(SessionLost):
        w.adapter.reset(h, ResetScope.CONTEXT)


def test_close_session_reports_what_was_released_and_is_idempotent():
    w = make_world(login_page())
    h = w.open()
    report = w.adapter.close_session(h)
    assert report.verified and report.leaked == () and set(report.released) == {"context", "page"}
    assert report.handle_id == h.session_id and report.closed_at == "2026-01-01T00:00:00Z"
    assert w.adapter.close_session(h) is report
    assert w.driver.sessions[h.session_id].closed


def test_a_leak_makes_the_report_unverified_and_a_failing_close_does_too():
    w = make_world(login_page())
    w.driver.leak_on_close = True
    report = w.adapter.close_session(w.open())
    assert not report.verified and report.leaked == ("context",)
    w2 = make_world(login_page())
    w2.driver.fail_close = True
    report2 = w2.adapter.close_session(w2.open())
    assert not report2.verified and report2.leaked == ("context",)


def test_every_call_on_a_closed_session_is_session_lost():
    w = make_world(login_page())
    h = w.open()
    w.adapter.close_session(h)
    from agent_harness.qa.records import CaptureKind, LocateMode, ObserveRequest, Phase
    for call in (lambda: w.adapter.observe(h, ObserveRequest(phase=Phase.BEFORE, step_id="s")),
                 lambda: w.adapter.locate(h, desc("button", "Submit"), mode=LocateMode.EXACT),
                 lambda: w.adapter.capture(h, [CaptureKind.A11Y_SNAPSHOT]),
                 lambda: w.adapter.reset(h, ResetScope.CONTEXT)):
        with pytest.raises(SessionLost):
            call()


def test_a_session_lost_under_us_is_session_lost_and_still_closes_cleanly():
    w = make_world(login_page())
    h = w.open()
    w.driver.lose(h.session_id)
    from agent_harness.qa.records import LocateMode
    with pytest.raises(SessionLost) as err:
        w.adapter.locate(h, desc("button", "Submit"), mode=LocateMode.EXACT)
    assert err.value.code == "SESSION_LOST" and err.value.recoverable
    report = w.adapter.close_session(h)
    assert report.handle_id == h.session_id


def test_an_unknown_handle_is_session_lost_and_a_foreign_object_is_refused():
    w = make_world(login_page())
    with pytest.raises(SessionLost):
        w.adapter.close_session(SessionHandle(session_id="sess-999"))
    with pytest.raises(UnsupportedOperation):
        w.adapter.close_session("sess-1")


def test_open_session_refuses_a_redaction_policy_other_than_the_adapters_and_an_unknown_egress_profile():
    w = make_world(login_page())
    other = "rcv1:" + "0" * 64
    with pytest.raises(RedactionFailed):
        w.adapter.open_session(SessionProfile(egress_profile=PROFILE_ID, redaction_policy_id=other))
    with pytest.raises(UnsupportedOperation):
        w.adapter.open_session(SessionProfile(egress_profile="nope", redaction_policy_id=w.redactor.policy_id))
    with pytest.raises(UnsupportedOperation):
        w.adapter.open_session({"egress_profile": PROFILE_ID})


def test_an_unavailable_driver_is_a_typed_error_and_no_session_exists_afterwards():
    from qa_playwright import DriverUnavailable
    w = make_world(login_page())
    w.driver.unavailable = True
    with pytest.raises(DriverUnavailable) as err:
        w.open()
    assert err.value.code == "ENVIRONMENT_UNHEALTHY" and not err.value.recoverable
    with pytest.raises(SessionLost):
        w.adapter.close_session(SessionHandle(session_id="sess-1"))


def test_shutdown_closes_open_sessions_and_the_driver():
    w = make_world(login_page())
    a, b = w.open(), w.open()
    w.adapter.close_session(a)
    w.adapter.shutdown()
    assert w.driver.closed and w.driver.sessions[b.session_id].closed
