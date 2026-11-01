# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The three behaviours of the real driver that the real-browser lane found wrong, proved offline against the fake
``playwright.sync_api``: redirect hops go through the request gate before they are requested, a non-form element is "not
editable" rather than an error, and an element keeps its ref across queries (so the adapter's re-verify finds it)."""
import pytest
from qa_playwright import ContextSpec, DriverFault, FaultKind, PlaywrightDriver
from qa_playwright.playwright_driver import PlaywrightSession, _resolve_location

from qa_pw_fakepw import Error, FakeSyncApi


def paused(url, status, location=None, *, resource="Document", request_id="r1", method="GET"):
    headers = [{"name": "Content-Type", "value": "text/html"}]
    if location is not None:
        headers.append({"name": "Location", "value": location})
    event = {"requestId": request_id, "request": {"url": url, "method": method}, "resourceType": resource,
             "responseStatusCode": status, "responseHeaders": headers}
    return event


class Lane:
    """A driver over the fake API, one session, a gate that records what it was asked."""

    def __init__(self, allow=lambda info: True, gate=True):
        self.asked = []

        def request_gate(info):
            self.asked.append(info)
            return allow(info)
        api = FakeSyncApi()
        self.driver = PlaywrightDriver(module=api)
        self.world = api.world
        self.session = self.driver.new_session(ContextSpec(session_id="s", profile_id="p",
                                                           request_gate=request_gate if gate else None))

    def fire(self, event):
        (cdp,) = self.world.cdp_sessions
        self.session._run(lambda: cdp.handlers["Fetch.requestPaused"](event))     # on the worker, like the real events
        return cdp.sent[-1]

    def close(self):
        self.driver.close()


@pytest.fixture()
def lane():
    made = []

    def make(**kw):
        made.append(Lane(**kw))
        return made[-1]
    yield make
    for one in made:
        one.close()


def test_a_redirect_hop_to_a_listed_host_is_continued_after_the_gate_decided_it(lane):
    l = lane(allow=lambda info: info.url == "http://app.test/next")
    sent = l.fire(paused("http://app.test/go", 302, "/next"))
    assert sent == ("Fetch.continueResponse", {"requestId": "r1"})
    (info,) = l.asked
    assert info.url == "http://app.test/next" and info.is_navigation and info.resource_type == "document"


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_hop_the_gate_refuses_is_failed_before_it_is_requested_and_is_logged_as_blocked(lane, status):
    l = lane(allow=lambda info: "evil.test" not in info.url)
    sent = l.fire(paused("http://app.test/go", status, "http://evil.test/landing", resource="XHR", method="POST"))
    assert sent == ("Fetch.failRequest", {"requestId": "r1", "errorReason": "BlockedByClient"})
    (event,) = l.session.network_log().events
    assert event.blocked and event.url == "http://evil.test/landing" and event.method == "POST" and event.resource_type == "xhr"


@pytest.mark.parametrize("location,resolved", [
    ("http://evil.test/x", "http://evil.test/x"),
    ("//evil.test/x", "http://evil.test/x"),
    ("/x?y=1", "http://app.test:8080/x?y=1"),
    ("x/y", "http://app.test:8080/x/y"),
    ("?q", "http://app.test:8080/?q"),
    ("data:text/html,hi", "data:text/html,hi")])
def test_a_location_is_resolved_against_the_origin_of_the_request(location, resolved):
    assert _resolve_location("http://app.test:8080/a/b?c", location) == resolved


@pytest.mark.parametrize("location", ["\\\\evil.test/x", "/\\evil.test", "/x\ny", "/x y", "\t//evil.test"])
def test_a_location_in_a_form_that_is_not_modelled_is_refused(location):
    with pytest.raises(ValueError):
        _resolve_location("http://app.test/a", location)


def test_an_unmodelled_or_failing_decision_fails_the_hop_closed(lane):
    l = lane()
    assert l.fire(paused("http://app.test/go", 302, "\\\\evil.test/x"))[0] == "Fetch.failRequest"
    assert l.asked == []                                                   # refused before the gate was even asked

    def boom(info):
        raise RuntimeError("gate fault")
    l2 = lane(allow=boom)
    assert l2.fire(paused("http://app.test/go", 302, "/next"))[0] == "Fetch.failRequest"


def test_a_response_that_is_not_a_redirect_is_continued_untouched_and_the_gate_is_not_asked_again(lane):
    l = lane(allow=lambda info: False)                                     # the gate would refuse everything
    assert l.fire(paused("http://app.test/page", 200))[0] == "Fetch.continueResponse"
    assert l.fire(paused("http://app.test/page", 404))[0] == "Fetch.continueResponse"
    assert l.fire(paused("http://app.test/page", 304, None))[0] == "Fetch.continueResponse"
    assert l.fire(paused("http://app.test/page", 302, None))[0] == "Fetch.continueResponse"      # no Location: not followed
    assert l.asked == []


def test_the_interception_is_set_up_only_for_a_response_stage_on_a_session_that_has_a_gate(lane):
    l = lane()
    (cdp,) = l.world.cdp_sessions
    assert cdp.sent[0] == ("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Response"}]})
    assert not lane(gate=False).world.cdp_sessions


def test_a_page_that_went_away_while_the_hop_was_decided_is_not_an_error(lane):
    l = lane()
    (cdp,) = l.world.cdp_sessions

    def gone(method, params=None):
        raise Error("Target closed")
    cdp.send = gone
    l.session._run(lambda: cdp.handlers["Fetch.requestPaused"](paused("http://app.test/go", 302, "/next")))


FRAME = object()


class Handle:
    def __init__(self, same_as=None, frame=FRAME):
        self.disposed = False
        self.token = same_as
        self.frame = frame

    def owner_frame(self):
        return self.frame

    def evaluate(self, script, others):
        assert "findIndex" in script
        assert all(o.frame is self.frame for o in others), "a handle of another frame was passed to the page"
        return next((i for i, o in enumerate(others) if o.token == self.token), -1)

    def dispose(self):
        self.disposed = True


def bare_session():
    s = PlaywrightSession.__new__(PlaywrightSession)
    s._handles, s._counter = {}, 0
    s._closed = s._crashed = False

    class Page:
        @staticmethod
        def is_closed():
            return False
    s._page = Page()
    return s


def test_an_element_keeps_its_ref_across_queries_and_a_different_element_gets_a_new_one():
    s = bare_session()
    first = Handle("a")
    assert s._ref_for(first) == ("e1", first)
    again = Handle("a")                                                    # Playwright hands out a new handle every query
    assert s._ref_for(again) == ("e1", first) and again.disposed and not first.disposed
    other = Handle("b")
    assert s._ref_for(other) == ("e2", other)
    assert sorted(s._handles) == ["e1", "e2"]


def test_only_the_handles_of_the_same_frame_are_compared_and_the_same_token_in_another_frame_is_another_element():
    s = bare_session()
    outer = Handle("a")
    assert s._ref_for(outer) == ("e1", outer)
    inner = Handle("a", frame=object())                                    # the same token, but in another frame's document
    assert s._ref_for(inner) == ("e2", inner) and not inner.disposed and not outer.disposed


def test_a_non_form_element_is_not_editable_and_any_other_failure_is_still_classified():
    s = bare_session()

    class Button:
        @staticmethod
        def is_editable():
            raise Error("ElementHandle.is_editable: Error: Element is not an <input>, <textarea>, <select> or [contenteditable] "
                        "and does not have a role allowing [aria-readonly]")

    class Gone:
        @staticmethod
        def is_editable():
            raise Error("Element is not attached to the DOM")

    class Field:
        @staticmethod
        def is_editable():
            return True
    assert s._editable(Button()) is False and s._editable(Field()) is True
    with pytest.raises(DriverFault) as err:
        s._editable(Gone())
    assert err.value.kind is FaultKind.DETACHED
