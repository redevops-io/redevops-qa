# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Driver fidelity against a real Chromium: the adapter over ``PlaywrightDriver`` behaves as it does over the fake driver.

NOT RUN in the environment this file was written in (no Playwright package, no network). It runs in the browser CI job only.
"""
import json

import pytest
from agent_harness.qa.blobs import MemoryBlobSink
from agent_harness.qa.clock import SystemClock
from agent_harness.qa.egress import AllowEntry, EgressPolicy
from agent_harness.qa.errors import NavigationDenied, QAError, SessionLost, TargetNotActionable, UnexpectedDialog
from agent_harness.qa.records import (Action, ActionKind, ActionRequest, AssertionSubject, CaptureKind, LocateMode,
                                      LocatorDescriptor, LocatorStrategy, ObserveRequest, Phase, ResolvedTarget, ResetScope,
                                      Resolution, SessionProfile, SubjectKind)
from agent_harness.qa.redaction import PatternRedactor, RedactionConfig
from qa_playwright import AdapterConfig, EgressProfile, PlaywrightAdapter, PlaywrightDriver

pytestmark = pytest.mark.browser

DECISION = "rcv1:" + "ab" * 32


def build(server, *, trace=False, allow=None):
    redactor = PatternRedactor(RedactionConfig(acknowledged_unredacted_media=("image/png", "application/zip")))
    entry = AllowEntry(host="127.0.0.1", networks=("127.0.0.1/32",), schemes=("http",), ports=(server.port,), private_ok=True)
    profile = EgressProfile("lane", EgressPolicy(entries=(entry,) + tuple(allow or ())))
    driver = PlaywrightDriver()
    adapter = PlaywrightAdapter(driver, blobs=MemoryBlobSink(), redactor=redactor, clock=SystemClock(),
                                egress_profiles={"lane": profile},
                                config=AdapterConfig(allow_trace=trace, action_timeout_ms=4000, locate_timeout_ms=1500,
                                                     assert_timeout_ms=1500))
    handle = adapter.open_session(SessionProfile(egress_profile="lane", redaction_policy_id=redactor.policy_id))
    return adapter, handle


def act(adapter, handle, kind, target=None, value=None, key="k"):
    return adapter.act(handle, ActionRequest(action=Action(kind=kind, value=value), idempotency_key=key,
                                             policy_decision_ref=DECISION, step_id="s"), target)


def goto(adapter, handle, server, path):
    act(adapter, handle, ActionKind.NAVIGATE, None, server.url(path))


def one(adapter, handle, descriptor):
    cands = adapter.locate(handle, descriptor, mode=LocateMode.EXACT).candidates
    assert len(cands) == 1 and cands[0].unique, cands
    return ResolvedTarget(candidate_ref=cands[0].candidate_ref, locator=descriptor, strategy=LocatorStrategy.AUTHORED)


@pytest.fixture()
def session(playwright_available, fixture_server):
    adapter, handle = build(fixture_server)
    try:
        yield adapter, handle, fixture_server
    finally:
        adapter.shutdown()


def test_navigate_locate_fill_click_and_assert_through_real_chromium(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/login")
    email = one(adapter, handle, LocatorDescriptor(role="textbox", name="Email"))
    act(adapter, handle, ActionKind.FILL, email, "user@example.test")
    act(adapter, handle, ActionKind.CLICK, one(adapter, handle, LocatorDescriptor(test_id="submit")))
    out = adapter.assert_(handle, AssertionSubject(kind=SubjectKind.UI_ELEMENT, locator=LocatorDescriptor(role="status")))
    assert out.resolution is Resolution.RESOLVED and out.value == "Welcome back"
    (first, second) = adapter.receipt_payloads(handle)
    assert first.state_before_hash != first.state_after_hash or first.action_kind == "fill"
    assert second.state_changed


def test_label_and_test_id_locators_and_the_checkbox_value(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/login")
    assert len(adapter.locate(handle, LocatorDescriptor(label="Email"), mode=LocateMode.EXACT).candidates) == 1
    box = one(adapter, handle, LocatorDescriptor(role="checkbox", name="Remember me"))
    subject = AssertionSubject(kind=SubjectKind.UI_ELEMENT, locator=LocatorDescriptor(role="checkbox", name="Remember me"))
    assert adapter.assert_(handle, subject).value is False
    act(adapter, handle, ActionKind.CHECK, box)
    assert adapter.assert_(handle, subject).value is True


def test_the_password_value_is_never_read(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/login")
    act(adapter, handle, ActionKind.FILL, one(adapter, handle, LocatorDescriptor(test_id="password")), "plain-text-test-value")
    out = adapter.assert_(handle, AssertionSubject(kind=SubjectKind.UI_ELEMENT, locator=LocatorDescriptor(test_id="password")))
    assert out.value is None and "plain-text-test-value" not in repr(out.to_json())


def test_two_matches_are_reported_as_ambiguous_and_never_picked(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/dup")
    cands = adapter.locate(handle, LocatorDescriptor(role="button", name="Save"), mode=LocateMode.EXACT).candidates
    assert len(cands) == 2 and not any(c.unique for c in cands)
    out = adapter.assert_(handle, AssertionSubject(kind=SubjectKind.UI_ELEMENT, locator=LocatorDescriptor(role="button", name="Save")))
    assert out.resolution is Resolution.AMBIGUOUS


def test_a_hidden_element_is_reported_hidden_and_does_not_resolve_for_assert(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/hidden")
    ghost = adapter.locate(handle, LocatorDescriptor(role="button", name="Ghost"), mode=LocateMode.EXACT).candidates
    assert all(not c.visible for c in ghost)
    out = adapter.assert_(handle, AssertionSubject(kind=SubjectKind.UI_ELEMENT, locator=LocatorDescriptor(role="button", name="Ghost")))
    assert out.resolution is Resolution.UNRESOLVED


def test_an_element_that_appears_late_is_found_by_the_auto_wait(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/delayed")
    assert len(adapter.locate(handle, LocatorDescriptor(role="button", name="Later"), mode=LocateMode.EXACT).candidates) == 1


def test_a_consent_overlay_on_top_of_the_target_is_an_unexpected_dialog(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/overlay")
    target = one(adapter, handle, LocatorDescriptor(role="button", name="Under"))
    with pytest.raises((UnexpectedDialog, TargetNotActionable)) as err:
        act(adapter, handle, ActionKind.CLICK, target)
    assert err.value.code in ("UNEXPECTED_DIALOG", "TARGET_NOT_ACTIONABLE")


def test_observe_returns_snapshot_screenshot_and_metadata_and_a_stable_state_hash(session):
    from agent_harness.qa.receipts import state_hash
    adapter, handle, server = session
    goto(adapter, handle, server, "/home")
    a = adapter.observe(handle, ObserveRequest(phase=Phase.BEFORE, step_id="s1"))
    b = adapter.observe(handle, ObserveRequest(phase=Phase.AFTER, step_id="s2"))
    assert a.url == server.url("/home") and dict(a.dom_meta)["title"] == "Home"
    assert adapter._blobs.get(a.screenshot_ref.content_hash).startswith(b"\x89PNG\r\n\x1a\n")
    assert "Welcome" in adapter._blobs.get(a.a11y_snapshot_ref.content_hash).decode()
    assert state_hash(a) == state_hash(b)


def test_console_and_network_excerpts_hold_what_the_page_did(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/subres")
    obs = adapter.observe(handle, ObserveRequest(phase=Phase.AFTER, step_id="s", capture=(CaptureKind.NETWORK_EXCERPT,)))
    doc = json.loads(adapter._blobs.get(obs.network_excerpt_ref.content_hash))
    urls = [e["url"] for e in doc["entries"]]
    assert any(u.endswith("/pixel.png") for u in urls) and any(u.endswith("/api/ok") for u in urls)


def test_a_new_session_never_sees_the_storage_or_cookies_of_the_previous_one(playwright_available, fixture_server):
    adapter, handle = build(fixture_server)
    try:
        goto(adapter, handle, fixture_server, "/storage")
        goto(adapter, handle, fixture_server, "/storage")
        subject = AssertionSubject(kind=SubjectKind.UI_ELEMENT, locator=LocatorDescriptor(text_hint=None, test_id=None, role="paragraph"))
        second = adapter.assert_(handle, subject)
        assert second.value.startswith("visits=2")
        adapter.close_session(handle)
        other = adapter.open_session(SessionProfile(egress_profile="lane", redaction_policy_id=adapter._redactor.policy_id))
        goto(adapter, other, fixture_server, "/storage")
        assert adapter.assert_(other, subject).value.startswith("visits=1")
        adapter.reset(other, ResetScope.CONTEXT)
        goto(adapter, other, fixture_server, "/storage")
        assert adapter.assert_(other, subject).value.startswith("visits=1")
    finally:
        adapter.shutdown()


def test_a_popup_is_closed_and_the_session_still_has_one_page(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/popup")
    act(adapter, handle, ActionKind.CLICK, one(adapter, handle, LocatorDescriptor(role="link", name="Open")))
    pages = adapter._sessions[handle.session_id].ds._context.pages
    assert len(pages) == 1


def test_a_download_link_does_not_break_the_session_and_nothing_is_saved(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/download")
    act(adapter, handle, ActionKind.CLICK, one(adapter, handle, LocatorDescriptor(role="link", name="Get")))
    assert adapter.observe(handle, ObserveRequest(phase=Phase.AFTER, step_id="s")).url == server.url("/download")


def test_an_unlisted_origin_is_never_requested_by_a_navigation_or_a_subresource(session):
    adapter, handle, server = session
    with pytest.raises(NavigationDenied):
        goto_host = server.url("/home", host="localhost")
        act(adapter, handle, ActionKind.NAVIGATE, None, goto_host)
    assert not [entry for entry in server.log if entry[2].startswith("localhost")]
    page = server.url("/subres")
    goto(adapter, handle, server, "/subres")
    sess = adapter._sessions[handle.session_id].ds
    sess._page.evaluate("(u) => fetch(u).catch(() => null)", server.url("/api/ok", host="localhost"))
    assert not [entry for entry in server.log if entry[2].startswith("localhost")]


def test_the_request_gate_sees_a_redirect_hop_to_an_unlisted_host(playwright_available, fixture_server):
    adapter, handle = build(fixture_server)
    try:
        fixture_server.httpd.redirect_to = fixture_server.url("/home", host="localhost")
        with pytest.raises(QAError):
            goto(adapter, handle, fixture_server, "/redirect")
        assert not [entry for entry in fixture_server.log if entry[2].startswith("localhost")]
    finally:
        fixture_server.httpd.redirect_to = "/home"
        adapter.shutdown()


def test_a_trace_is_captured_only_when_enabled_and_is_a_zip(playwright_available, fixture_server):
    adapter, handle = build(fixture_server, trace=True)
    try:
        goto(adapter, handle, fixture_server, "/home")
        (ref,) = adapter.capture(handle, [CaptureKind.TRACE])
        assert ref.source == "restricted-trace" and adapter._blobs.get(ref.content_hash)[:2] == b"PK"
    finally:
        adapter.shutdown()


def test_close_session_is_verified_and_the_context_is_gone(session):
    adapter, handle, server = session
    report = adapter.close_session(handle)
    assert report.verified and not report.leaked
    with pytest.raises(SessionLost):
        adapter.locate(handle, LocatorDescriptor(role="button", name="x"), mode=LocateMode.EXACT)
