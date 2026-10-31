# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""act: the permitted kinds, a policy decision reference, auto-wait on the injected clock, typed errors, receipt payloads."""
import pytest
from agent_harness.qa.errors import (ActionBlockedByPolicy, ActionTimeout, AdapterCrash, BrowserCrash, EnvironmentUnhealthy,
                                     LocatorAmbiguous, LocatorNotFound, NavigationDenied, SessionLost, TargetNotActionable,
                                     UnexpectedDialog, UnsupportedOperation)
from agent_harness.qa.records import (ActionKind, LocateMode, LocatorStrategy, ObserveRequest, Phase, ResolvedTarget, SecretRef)
from agent_harness.qa.receipts import state_hash
from qa_playwright import AdapterConfig, DriverFault, FaultKind
from qa_playwright.testing.fake import FakeElement, FakePage

from qa_pw_support import APP, canary, desc, locate_one, login_page, make_world, rcv1, request


def opened(page=None, **kw):
    w = make_world(page or login_page(), **kw)
    h = w.open()
    w.driver.sessions[h.session_id]._load(page.url if page else f"{APP}/login")
    return w, h


def test_click_fill_press_select_check_uncheck_hover_and_resolve_are_supported():
    w, h = opened()
    sess = w.driver.sessions[h.session_id]
    email = locate_one(w, h, desc("textbox", "Email"))
    w.adapter.act(h, request(ActionKind.FILL, value="user@example.test"), email)
    assert [e for e in sess.page.elements if e.name == "Email"][0].value == "user@example.test"
    w.adapter.act(h, request(ActionKind.PRESS, value="Enter"), email)
    assert sess.typed == ["Enter"]
    w.adapter.act(h, request(ActionKind.SELECT, value="b"), email)
    box = locate_one(w, h, desc("checkbox", "Remember me"))
    w.adapter.act(h, request(ActionKind.CHECK), box)
    assert [e for e in sess.page.elements if e.kind == "checkbox"][0].checked
    w.adapter.act(h, request(ActionKind.UNCHECK), box)
    assert not [e for e in sess.page.elements if e.kind == "checkbox"][0].checked
    w.adapter.act(h, request(ActionKind.HOVER), locate_one(w, h, desc("button", "Submit")))
    out = w.adapter.act(h, request(ActionKind.RESOLVE), locate_one(w, h, desc("button", "Submit")))
    assert out.result.value == "OK" and out.detail is None
    clicked = []
    [e for e in sess.page.elements if e.name == "Submit"][0].on_click = lambda s, el: clicked.append(1)
    w.adapter.act(h, request(ActionKind.CLICK), locate_one(w, h, desc("button", "Submit")))
    assert clicked == [1]


def test_resolve_changes_nothing_on_the_page():
    w, h = opened()
    sess = w.driver.sessions[h.session_id]
    before = (sess.accessibility_snapshot(), tuple(sess.typed))
    w.adapter.act(h, request(ActionKind.RESOLVE), locate_one(w, h, desc("button", "Submit")))
    assert (sess.accessibility_snapshot(), tuple(sess.typed)) == before


@pytest.mark.parametrize("kind", [ActionKind.FILL, ActionKind.PRESS, ActionKind.SELECT])
def test_actions_that_need_a_value_refuse_without_one(kind):
    w, h = opened()
    with pytest.raises(UnsupportedOperation):
        w.adapter.act(h, request(kind), locate_one(w, h, desc("textbox", "Email")))


def test_an_action_without_a_policy_decision_reference_is_blocked_before_the_driver_is_touched():
    w, h = opened()
    target = locate_one(w, h, desc("button", "Submit"))
    calls = len(w.driver.calls)
    for bad in (None, {"policy_decision_ref": "rcv1:" + "0" * 64}, "plain text"):
        with pytest.raises(ActionBlockedByPolicy):
            w.adapter.act(h, bad, target)
    assert len(w.driver.calls) == calls


def test_a_decision_reference_the_check_hook_does_not_accept_is_blocked():
    accepted = {rcv1("ok")}
    w, h = opened(decision_check=lambda ref: ref in accepted)
    target = locate_one(w, h, desc("button", "Submit"))
    w.adapter.act(h, request(ActionKind.CLICK, ref=rcv1("ok")), target)
    with pytest.raises(ActionBlockedByPolicy):
        w.adapter.act(h, request(ActionKind.CLICK, ref=rcv1("other")), target)
    w2, h2 = opened(decision_check=lambda ref: 1 / 0)
    with pytest.raises(ActionBlockedByPolicy):
        w2.adapter.act(h2, request(ActionKind.CLICK), locate_one(w2, h2, desc("button", "Submit")))


def test_a_target_that_locate_never_produced_is_not_found_and_one_with_the_wrong_locator_is_refused():
    w, h = opened()
    ghost = ResolvedTarget(candidate_ref="cand-1-999", locator=desc("button", "Submit"), strategy=LocatorStrategy.AUTHORED)
    with pytest.raises(LocatorNotFound):
        w.adapter.act(h, request(ActionKind.CLICK), ghost)
    real = locate_one(w, h, desc("button", "Submit"))
    wrong = ResolvedTarget(candidate_ref=real.candidate_ref, locator=desc("button", "Other"), strategy=LocatorStrategy.AUTHORED)
    with pytest.raises(UnsupportedOperation):
        w.adapter.act(h, request(ActionKind.CLICK), wrong)
    with pytest.raises(UnsupportedOperation):
        w.adapter.act(h, request(ActionKind.CLICK), None)


def test_a_stale_element_after_a_rerender_is_locator_not_found_and_a_fresh_locate_works():
    w, h = opened()
    target = locate_one(w, h, desc("button", "Submit"))
    w.driver.sessions[h.session_id].rerender()
    with pytest.raises(LocatorNotFound) as err:
        w.adapter.act(h, request(ActionKind.CLICK), target)
    assert err.value.recoverable
    w.adapter.act(h, request(ActionKind.CLICK), locate_one(w, h, desc("button", "Submit")))


def test_a_target_that_became_ambiguous_after_locate_is_refused_not_guessed():
    w, h = opened()
    target = locate_one(w, h, desc("button", "Submit"))
    w.driver.sessions[h.session_id].page.elements.append(FakeElement(role="button", name="Submit", key="dup"))
    with pytest.raises(LocatorAmbiguous):
        w.adapter.act(h, request(ActionKind.CLICK), target)


def test_a_non_unique_candidate_is_never_acted_on_even_if_the_caller_insists():
    page = FakePage(url=f"{APP}/p", elements=[FakeElement(role="button", name="Save"), FakeElement(role="button", name="Save")])
    w, h = opened(page)
    cands = w.adapter.locate(h, desc("button", "Save"), mode=LocateMode.EXACT).candidates
    forced = ResolvedTarget(candidate_ref=cands[0].candidate_ref, locator=desc("button", "Save"), strategy=LocatorStrategy.AUTHORED)
    with pytest.raises(LocatorAmbiguous):
        w.adapter.act(h, request(ActionKind.CLICK), forced)


def test_a_delayed_enabled_state_is_waited_for_on_the_injected_clock():
    page = FakePage(url=f"{APP}/p", elements=[FakeElement(role="button", name="Go", enabled_after_ms=700)])
    w, h = opened(page)
    start = w.clock.ms
    w.adapter.act(h, request(ActionKind.CLICK), locate_one(w, h, desc("button", "Go")))
    assert 700 <= w.clock.ms - start < 1200


def test_a_target_that_never_becomes_actionable_times_out_as_target_not_actionable_on_the_deadline():
    page = FakePage(url=f"{APP}/p", elements=[FakeElement(role="button", name="Off", enabled_after_ms=10**7),
                                              FakeElement(role="button", name="Ghost", visible_after_ms=10**7)])
    w, h = opened(page, config=AdapterConfig(action_timeout_ms=1000))
    for name, reason in (("Off", "disabled"), ("Ghost", "hidden")):
        start = w.clock.ms
        with pytest.raises(TargetNotActionable) as err:
            w.adapter.act(h, request(ActionKind.CLICK), locate_one(w, h, desc("button", name)))
        assert err.value.details["reason"] == reason and err.value.retryable
        assert 1000 <= w.clock.ms - start < 1400


def test_a_cover_that_goes_away_is_waited_out_and_a_dialog_that_stays_is_unexpected_dialog():
    page = FakePage(url=f"{APP}/p", elements=[FakeElement(role="button", name="Under", covered_until_ms=500),
                                              FakeElement(role="button", name="Blocked", covered_until_ms=10**7),
                                              FakeElement(role="button", name="Banner", covered_until_ms=10**7, covered_by="banner")])
    w, h = opened(page, config=AdapterConfig(action_timeout_ms=1500))
    w.adapter.act(h, request(ActionKind.CLICK), locate_one(w, h, desc("button", "Under")))
    with pytest.raises(UnexpectedDialog):
        w.adapter.act(h, request(ActionKind.CLICK), locate_one(w, h, desc("button", "Blocked")))
    with pytest.raises(TargetNotActionable) as err:
        w.adapter.act(h, request(ActionKind.CLICK), locate_one(w, h, desc("button", "Banner")))
    assert err.value.details["reason"] == "obscured"


def test_fill_on_a_non_editable_target_is_not_actionable():
    w, h = opened()
    with pytest.raises(TargetNotActionable) as err:
        w.adapter.act(h, request(ActionKind.FILL, value="x"), locate_one(w, h, desc("button", "Submit")))
    assert err.value.details["reason"] == "not_editable"


def test_a_slow_action_is_action_timeout_with_the_clock_at_the_deadline():
    w, h = opened(config=AdapterConfig(action_timeout_ms=800))
    w.driver.sessions[h.session_id].action_delay_ms = 5000
    start = w.clock.ms
    with pytest.raises(ActionTimeout) as err:
        w.adapter.act(h, request(ActionKind.CLICK), locate_one(w, h, desc("button", "Submit")))
    assert err.value.retryable and w.clock.ms - start <= 800 + 100


@pytest.mark.parametrize("kind,error,code", [
    (FaultKind.SESSION_CLOSED, SessionLost, "SESSION_LOST"), (FaultKind.CRASHED, BrowserCrash, "BROWSER_CRASH"),
    (FaultKind.TIMEOUT, ActionTimeout, "ACTION_TIMEOUT"), (FaultKind.DETACHED, LocatorNotFound, "LOCATOR_NOT_FOUND"),
    (FaultKind.NOT_VISIBLE, TargetNotActionable, "TARGET_NOT_ACTIONABLE"),
    (FaultKind.DISABLED, TargetNotActionable, "TARGET_NOT_ACTIONABLE"),
    (FaultKind.NOT_EDITABLE, TargetNotActionable, "TARGET_NOT_ACTIONABLE"),
    (FaultKind.OBSCURED, TargetNotActionable, "TARGET_NOT_ACTIONABLE"),
    (FaultKind.NAVIGATION_BLOCKED, NavigationDenied, "NAVIGATION_DENIED"),
    (FaultKind.DIALOG, UnexpectedDialog, "UNEXPECTED_DIALOG"), (FaultKind.LIMIT, __import__("agent_harness.qa.errors", fromlist=["x"]).ResourceLimitExceeded, "RESOURCE_LIMIT_EXCEEDED"),
    (FaultKind.INVALID, UnsupportedOperation, "UNSUPPORTED_OPERATION"), (FaultKind.OTHER, AdapterCrash, "ADAPTER_CRASH")])
def test_every_driver_fault_kind_maps_to_one_harness_error_code(kind, error, code):
    w, h = opened()
    target = locate_one(w, h, desc("button", "Submit"))
    w.driver.sessions[h.session_id].fail_next = DriverFault(kind)
    with pytest.raises(error) as err:
        w.adapter.act(h, request(ActionKind.CLICK), target)
    assert err.value.code == code
    assert str(err.value) and "Submit" not in str(err.value)


def test_a_dialog_covering_the_target_through_the_driver_is_unexpected_dialog():
    w, h = opened()
    target = locate_one(w, h, desc("button", "Submit"))
    w.driver.sessions[h.session_id].fail_next = DriverFault(FaultKind.OBSCURED, obscurer_role="dialog")
    with pytest.raises(UnexpectedDialog):
        w.adapter.act(h, request(ActionKind.CLICK), target)


def test_an_unexpected_exception_from_the_driver_is_an_adapter_crash_that_names_only_its_class():
    w, h = opened()
    target = locate_one(w, h, desc("button", "Submit"))

    def boom(*args):
        raise ValueError("page text: " + canary("boom"))
    w.driver.sessions[h.session_id].perform = boom
    with pytest.raises(AdapterCrash) as err:
        w.adapter.act(h, request(ActionKind.CLICK), target)
    assert err.value.details == {"cause": "ValueError"} and canary("boom") not in str(err.value) and "page text" not in str(err.value)


def test_a_crashed_browser_makes_the_session_unusable_afterwards():
    w, h = opened()
    w.driver.sessions[h.session_id].crashed = True
    with pytest.raises(Exception) as err:
        w.adapter.locate(h, desc("button", "Submit"), mode=LocateMode.EXACT)
    assert err.value.code == "BROWSER_CRASH"
    with pytest.raises(SessionLost):
        w.adapter.locate(h, desc("button", "Submit"), mode=LocateMode.EXACT)


# ---- navigation --------------------------------------------------------------------------------------------

def test_navigate_to_an_allowed_origin_loads_the_page_and_a_denied_one_is_navigation_denied_by_host_only():
    w = make_world(login_page())
    h = w.open()
    w.adapter.act(h, request(ActionKind.NAVIGATE, value=f"{APP}/login"), None)
    assert w.driver.sessions[h.session_id].page.url == f"{APP}/login"
    with pytest.raises(NavigationDenied):
        w.adapter.act(h, request(ActionKind.NAVIGATE, value="http://169.254.169.254/latest/meta-data/?k=v"), None)
    with pytest.raises(NavigationDenied):
        w.adapter.act(h, request(ActionKind.NAVIGATE, value="http://evil.test/"), None)
    counts = w.adapter.egress_counts(h)
    assert ["169.254.169.254", 1] in counts["denied_hosts"] and ["evil.test", 1] in counts["denied_hosts"]
    assert "meta-data" not in repr(counts)


def test_navigate_needs_a_value_and_refuses_credentials_in_the_url():
    w = make_world(login_page())
    h = w.open()
    with pytest.raises(UnsupportedOperation):
        w.adapter.act(h, request(ActionKind.NAVIGATE), None)
    with pytest.raises(NavigationDenied):
        w.adapter.act(h, request(ActionKind.NAVIGATE, value="http://user:pw@app.test/"), None)


def test_a_navigation_denied_by_the_browser_level_gate_after_the_adapter_check_is_still_navigation_denied():
    w = make_world(login_page())
    h = w.open()
    w.site.redirects[f"{APP}/go"] = "http://evil.test/landing"          # a redirect hop to an unlisted host
    with pytest.raises(NavigationDenied):
        w.adapter.act(h, request(ActionKind.NAVIGATE, value=f"{APP}/go"), None)
    assert w.driver.sessions[h.session_id].network[-1].blocked


# ---- secrets -----------------------------------------------------------------------------------------------

def test_a_secret_ref_is_resolved_by_the_injected_resolver_and_the_value_never_reaches_a_receipt_or_a_blob():
    secret_value = "pw-" + __import__("hashlib").sha256(b"x").hexdigest()[:12]
    ref = SecretRef(provider="vault", key="login-password")
    w, h = opened(secret_resolver=lambda r: secret_value if r == ref else "wrong")
    target = locate_one(w, h, desc("textbox", "Email"))
    w.adapter.act(h, request(ActionKind.FILL, secret_ref=ref), target)
    (payload,) = w.adapter.receipt_payloads(h)
    assert secret_value not in repr(payload.to_json())
    assert payload.value_digest and payload.value_digest.startswith("rcv1:")
    assert all(secret_value.encode() not in w.blobs.get(d) for d in w.blobs.digests())


def test_a_secret_ref_without_a_resolver_is_unsupported_and_a_failing_resolver_is_environment_unhealthy():
    ref = SecretRef(provider="vault", key="k")
    w, h = opened()
    with pytest.raises(UnsupportedOperation):
        w.adapter.act(h, request(ActionKind.FILL, secret_ref=ref), locate_one(w, h, desc("textbox", "Email")))
    w2, h2 = opened(secret_resolver=lambda r: 1 / 0)
    with pytest.raises(EnvironmentUnhealthy) as err:
        w2.adapter.act(h2, request(ActionKind.FILL, secret_ref=ref), locate_one(w2, h2, desc("textbox", "Email")))
    assert "division" not in str(err.value)
    w3, h3 = opened(secret_resolver=lambda r: None)
    with pytest.raises(EnvironmentUnhealthy):
        w3.adapter.act(h3, request(ActionKind.FILL, secret_ref=ref), locate_one(w3, h3, desc("textbox", "Email")))


# ---- receipt payloads --------------------------------------------------------------------------------------

def test_the_receipt_payload_has_the_exact_locator_the_action_and_state_hashes_equal_observe_hashes():
    w, h = opened()
    page_el = [e for e in w.driver.sessions[h.session_id].page.elements if e.name == "Submit"][0]
    page_el.on_click = lambda s, el: s.page.elements.append(FakeElement(role="alert", name="Welcome", text="Welcome back"))
    before_obs = w.adapter.observe(h, ObserveRequest(phase=Phase.BEFORE, step_id="step-1"))
    descriptor = desc("button", "Submit")
    target = locate_one(w, h, descriptor)
    w.adapter.act(h, request(ActionKind.CLICK, step="step-1", key="k-9"), target)
    after_obs = w.adapter.observe(h, ObserveRequest(phase=Phase.AFTER, step_id="step-1"))
    (payload,) = w.adapter.receipt_payloads(h)
    assert payload.state_before_hash == state_hash(before_obs)
    assert payload.state_after_hash == state_hash(after_obs)
    assert payload.state_changed
    assert payload.locator_used == descriptor and payload.strategy == "AUTHORED"
    assert (payload.action_kind, payload.step_id, payload.idempotency_key, payload.candidate_ref) == (
        "click", "step-1", "k-9", target.candidate_ref)
    assert payload.policy_decision_ref == rcv1("decision") and payload.result == "OK"
    assert payload.value_digest is None


def test_the_value_digest_is_the_harness_digest_of_the_value_and_never_the_value():
    from agent_harness.qa.receipts import json_value_digest
    w, h = opened()
    w.adapter.act(h, request(ActionKind.FILL, value="user@example.test"), locate_one(w, h, desc("textbox", "Email")))
    (payload,) = w.adapter.receipt_payloads(h)
    assert payload.value_digest == json_value_digest("user@example.test")
    assert "user@example.test" not in repr(payload.to_json())


def test_an_action_that_changes_nothing_has_equal_state_hashes_and_attempts_are_kept_in_order():
    w, h = opened()
    t = locate_one(w, h, desc("button", "Submit"))
    w.adapter.act(h, request(ActionKind.HOVER, key="k-1"), t)
    w.adapter.act(h, request(ActionKind.HOVER, key="k-1"), t)           # same key: a retry is performed, never skipped
    first, second = w.adapter.receipt_payloads(h)
    assert not first.state_changed and first.state_before_hash == second.state_before_hash
    assert len(w.driver.sessions[h.session_id].typed) == 0


def test_a_failed_action_leaves_no_receipt_payload():
    w, h = opened()
    target = locate_one(w, h, desc("button", "Submit"))
    w.driver.sessions[h.session_id].fail_next = DriverFault(FaultKind.TIMEOUT)
    with pytest.raises(ActionTimeout):
        w.adapter.act(h, request(ActionKind.CLICK), target)
    assert w.adapter.receipt_payloads(h) == ()


def test_navigation_receipt_has_no_locator_and_hashes_change():
    w = make_world(login_page())
    h = w.open()
    w.adapter.act(h, request(ActionKind.NAVIGATE, value=f"{APP}/login"), None)
    (payload,) = w.adapter.receipt_payloads(h)
    assert payload.locator_used is None and payload.candidate_ref is None and payload.state_changed
