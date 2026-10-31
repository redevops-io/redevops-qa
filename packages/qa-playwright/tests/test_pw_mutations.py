# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Mutation tests: each guard of the adapter is checked by a property function; the real adapter passes it and an adapter
with that one guard removed fails it. A guard that nothing would notice missing is not a guard."""
import json

import pytest
from agent_harness.qa.errors import (ActionBlockedByPolicy, LocatorAmbiguous, NavigationDenied, QAError, TargetNotActionable)
from agent_harness.qa.records import (ActionKind, AssertionSubject, CaptureKind, LocateMode, ObserveRequest, Phase, ResetScope,
                                      Resolution, SubjectKind)
from qa_playwright import AdapterConfig, DriverFault, FaultKind, PlaywrightAdapter
from qa_playwright.testing.fake import FakeElement, FakePage

from qa_pw_support import APP, canary, desc, element_subject, locate_one, login_page, make_world, request


def opened(cls, page=None, **kw):
    w = make_world(page or login_page(), adapter_cls=cls, **kw)
    h = w.open()
    w.driver.sessions[h.session_id]._load((page or login_page()).url)
    return w, h


# -- property functions: raise AssertionError (or a typed error they did not expect) when a guard is missing -----------

def check_redaction_with_denylist(cls):
    w = make_world(login_page(), adapter_cls=cls)
    page = w.site.pages[f"{APP}/login"]
    page.elements.append(FakeElement(role="paragraph", name="n", text=f"x {w.canary} y"))
    h = w.open()
    w.driver.sessions[h.session_id]._load(f"{APP}/login")
    w.adapter.observe(h, ObserveRequest(phase=Phase.BEFORE, step_id="s", capture=(CaptureKind.A11Y_SNAPSHOT,)))
    assert w.blobs.digests()
    for digest in w.blobs.digests():
        assert w.canary.encode() not in w.blobs.get(digest)


def check_policy_reference_required(cls):
    w, h = opened(cls)
    target = locate_one(w, h, desc("button", "Submit"))
    try:
        w.adapter.act(h, {"policy_decision_ref": None}, target)
    except ActionBlockedByPolicy:
        return
    raise AssertionError("an action without a decision reference was performed")


def check_uniqueness_flag(cls):
    page = FakePage(url=f"{APP}/p", elements=[FakeElement(role="button", name="Save"), FakeElement(role="button", name="Save")])
    w, h = opened(cls, page)
    cands = w.adapter.locate(h, desc("button", "Save"), mode=LocateMode.EXACT).candidates
    assert len(cands) == 2 and not any(c.unique for c in cands)


def check_act_reverifies_uniqueness(cls):
    w, h = opened(cls)
    target = locate_one(w, h, desc("button", "Submit"))
    w.driver.sessions[h.session_id].page.elements.append(FakeElement(role="button", name="Submit", key="dup"))
    try:
        w.adapter.act(h, request(ActionKind.CLICK), target)
    except LocatorAmbiguous:
        return
    raise AssertionError("acted on a target that was no longer unique")


def check_assert_never_picks_the_first(cls):
    page = FakePage(url=f"{APP}/p", elements=[FakeElement(role="heading", name="T", text="a"), FakeElement(role="heading", name="T", text="b")])
    w, h = opened(cls, page)
    out = w.adapter.assert_(h, element_subject(desc("heading", "T")))
    assert out.resolution is Resolution.AMBIGUOUS and out.value is None


def check_withheld_when_redacted(cls):
    w, h = opened(cls)
    [e for e in w.driver.sessions[h.session_id].page.elements if e.name == "Email"][0].value = "alice@example.test"
    out = w.adapter.assert_(h, element_subject(desc("textbox", "Email")))
    assert out.value is None


def check_password_never_read(cls):
    w, h = opened(cls)
    [e for e in w.driver.sessions[h.session_id].page.elements if e.name == "Password"][0].value = "plain-pass"
    out = w.adapter.assert_(h, element_subject(desc("textbox", "Password")))
    assert out.value is None


def check_context_reset_gives_a_blank_context(cls):
    w, h = opened(cls)
    sess = w.driver.sessions[h.session_id]
    sess.local_storage["k"] = "v"
    w.adapter.reset(h, ResetScope.CONTEXT)
    assert sess.local_storage == {} and sess.page.url == "about:blank"


def check_errors_carry_no_page_text(cls):
    w, h = opened(cls)
    target = locate_one(w, h, desc("button", "Submit"))

    def boom(*args):
        raise ValueError("PAGETEXT-" + "x")
    w.driver.sessions[h.session_id].perform = boom
    try:
        w.adapter.act(h, request(ActionKind.CLICK), target)
    except QAError as err:
        assert "PAGETEXT" not in str(err) + repr(err.details)
        return
    raise AssertionError("no error")


def check_waits_for_actionability(cls):
    page = FakePage(url=f"{APP}/p", elements=[FakeElement(role="button", name="Go", enabled_after_ms=400)])
    w, h = opened(cls, page)
    w.adapter.act(h, request(ActionKind.CLICK), locate_one(w, h, desc("button", "Go")))


def check_navigation_checked_against_the_allow_list(cls):
    w = make_world(login_page(), adapter_cls=cls)
    h = w.open()
    try:
        w.adapter.act(h, request(ActionKind.NAVIGATE, value="http://evil.test/"), None)
    except NavigationDenied:
        return
    raise AssertionError("navigated to an unlisted host")


def check_request_gate_denies_by_default(cls):
    w = make_world(login_page(), adapter_cls=cls)
    h = w.open()
    assert w.driver.sessions[h.session_id].fire_request("http://exfil.test/x") is False


def check_close_really_closes_the_context(cls):
    w, h = opened(cls)
    report = w.adapter.close_session(h)
    assert report.verified and w.driver.sessions[h.session_id].closed


class NoRedaction(PlaywrightAdapter):
    def _redact_bytes(self, data, media, cap):
        return bytes(data)


class NoPolicyCheck(PlaywrightAdapter):
    def _require_decision(self, action):
        return None

    def act(self, s, action, target):
        if not hasattr(action, "action"):
            return None                 # what a missing guard would do with garbage: carry on
        return super().act(s, action, target)


class AllUnique(PlaywrightAdapter):
    def locate(self, s, target, *, mode):
        from agent_harness.qa.records import LocateCandidate, LocateResult
        res = super().locate(s, target, mode=mode)
        return LocateResult(candidates=tuple(LocateCandidate(candidate_ref=c.candidate_ref, enabled=c.enabled, unique=True,
                                                             visible=c.visible, name=c.name, role=c.role) for c in res.candidates))


class NoReverify(PlaywrightAdapter):
    def _reverify(self, sess, cand):
        return None


class FirstWins(PlaywrightAdapter):
    def _visible(self, sess, query):
        return super()._visible(sess, query)[:1]


class RawValue(PlaywrightAdapter):
    def _value_result(self, value):
        return self._observed(Resolution.RESOLVED, 1, value, None)


class ReadsPasswords(PlaywrightAdapter):
    def _read_element(self, sess, info):
        reading = sess.ds.read(info.ref)
        return self._observed(Resolution.RESOLVED, 1, reading.text, None) if reading.kind != "text" else super()._read_element(sess, info)

    def _assert_element(self, sess, subject):
        infos = self._visible(sess, self._query(subject.locator, LocateMode.EXACT))
        driver_el = sess.ds._element(infos[0].ref)
        return self._observed(Resolution.RESOLVED, 1, driver_el.value, None)


class NoRealReset(PlaywrightAdapter):
    def reset(self, s, scope):
        from agent_harness.qa.records import ResetResult
        self._session(s)
        return ResetResult(ok=True, scope=scope)


class LeakyErrors(PlaywrightAdapter):
    def _drv(self, sess, fn, *args):
        from agent_harness.qa.errors import AdapterCrash
        try:
            return fn(*args)
        except QAError:
            raise
        except Exception as exc:
            raise AdapterCrash(f"driver failed: {exc}") from None


class NoWait(PlaywrightAdapter):
    def _poll(self, sess, probe, timeout_ms):
        return probe()


class NoNavCheck(PlaywrightAdapter):
    def act(self, s, action, target):
        sess = self._session(s)
        if action.action.kind is ActionKind.NAVIGATE:
            sess.ds.goto = lambda url, t: None
            sess.guard.check = lambda url, purpose="": type("D", (), {"allowed": True})()
        return super().act(s, action, target)


class OpenGate(PlaywrightAdapter):
    def _gate(self, sess):
        return lambda info: True


class ClaimsClosed(PlaywrightAdapter):
    def close_session(self, s):
        from agent_harness.qa.records import CleanupReport
        sess = self._session(s, closing=True)
        sess.report = CleanupReport(handle_id=sess.session_id, verified=True, leaked=(), released=("context",))
        return sess.report


MUTATIONS = [
    ("redaction removed", check_redaction_with_denylist, NoRedaction),
    ("policy reference not required", check_policy_reference_required, NoPolicyCheck),
    ("uniqueness flag always true", check_uniqueness_flag, AllUnique),
    ("act does not re-verify the target", check_act_reverifies_uniqueness, NoReverify),
    ("assert picks the first of several", check_assert_never_picks_the_first, FirstWins),
    ("a redacted value is returned as if intact", check_withheld_when_redacted, RawValue),
    ("a password value is read", check_password_never_read, ReadsPasswords),
    ("reset does not renew the context", check_context_reset_gives_a_blank_context, NoRealReset),
    ("error text includes the driver's text", check_errors_carry_no_page_text, LeakyErrors),
    ("no auto-wait", check_waits_for_actionability, NoWait),
    ("navigation not checked", check_navigation_checked_against_the_allow_list, NoNavCheck),
    ("browser-level gate lets everything through", check_request_gate_denies_by_default, OpenGate),
    ("a cleanup report that claims a close that did not happen", check_close_really_closes_the_context, ClaimsClosed),
]


@pytest.mark.parametrize("label,check,mutant", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_each_guard_is_noticed_when_it_is_removed(label, check, mutant):
    check(PlaywrightAdapter)                       # the real adapter passes the property
    with pytest.raises((AssertionError, QAError, AttributeError, TypeError)):
        check(mutant)                              # the mutant does not
