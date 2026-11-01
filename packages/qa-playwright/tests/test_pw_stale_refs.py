# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""An element reference belongs to the document it was resolved in. Proved offline over a fake ``playwright.sync_api`` that
has the real API's rule (a handle of a replaced document fails when used, see ``qa_pw_fakedom``): the same cases as the real-browser
test ``tests/browser/test_pw_browser_stale_refs.py``, plus the driver-level answers for a stale ref."""
import pytest
from agent_harness.qa.blobs import MemoryBlobSink
from agent_harness.qa.errors import LocatorNotFound, SessionLost
from agent_harness.qa.records import (Action, ActionKind, ActionRequest, LocateMode, LocatorDescriptor, LocatorStrategy,
                                      ResolvedTarget, SessionProfile)
from agent_harness.qa.redaction import PatternRedactor, RedactionConfig
from qa_playwright import (AdapterConfig, ContextSpec, DriverFault, EgressProfile, ElementQuery, FaultKind, PlaywrightAdapter,
                           PlaywrightDriver)
from qa_playwright.testing.fake import FakeClock

from qa_pw_fakedom import El, FakeDomApi
from qa_pw_support import PROFILE_ID, APP, default_policy, default_resolver, rcv1

EMAIL = LocatorDescriptor(role="textbox", name="Email")
SITE = {
    f"{APP}/login": [El("textbox", "Email"), El("button", "Submit")],
    f"{APP}/home": [El("heading", "Welcome")],
    f"{APP}/start": [El("link", "Next", goes_to=f"{APP}/login"), El("button", "Save")],
}


class Lane:
    def __init__(self):
        self.api = FakeDomApi(SITE)
        self.driver = PlaywrightDriver(module=self.api)
        redactor = PatternRedactor(RedactionConfig(acknowledged_unredacted_media=("image/png",)))
        self.adapter = PlaywrightAdapter(
            self.driver, blobs=MemoryBlobSink(), redactor=redactor, clock=FakeClock(),
            egress_profiles={PROFILE_ID: EgressProfile(PROFILE_ID, default_policy(), default_resolver())}, config=AdapterConfig())
        self.handle = self.adapter.open_session(SessionProfile(egress_profile=PROFILE_ID, redaction_policy_id=redactor.policy_id))
        self.n = 0

    def act(self, kind, target=None, value=None):
        self.n += 1
        return self.adapter.act(self.handle, ActionRequest(action=Action(kind=kind, value=value), idempotency_key=f"k{self.n}",
                                                           policy_decision_ref=rcv1(), step_id="s"), target)

    def goto(self, path):
        self.act(ActionKind.NAVIGATE, None, f"{APP}{path}")

    def one(self, descriptor):
        cands = self.adapter.locate(self.handle, descriptor, mode=LocateMode.EXACT).candidates
        assert len(cands) == 1 and cands[0].unique
        return ResolvedTarget(candidate_ref=cands[0].candidate_ref, locator=descriptor, strategy=LocatorStrategy.AUTHORED)

    @property
    def page(self):
        return self.api.world.page

    def field(self, name="Email"):
        return next(e for e in self.page.doc.elements if e.name == name)


@pytest.fixture()
def lane():
    made = Lane()
    yield made
    made.adapter.shutdown()


def test_locate_navigate_locate_and_act_works_after_every_navigation(lane):
    lane.goto("/login")
    lane.one(EMAIL)
    lane.goto("/home")
    lane.one(LocatorDescriptor(role="heading", name="Welcome"))        # the second locate after a navigation
    lane.goto("/login")
    lane.act(ActionKind.FILL, lane.one(EMAIL), "typed-text")
    assert lane.field().value == "typed-text"


def test_locate_works_after_a_click_that_navigates(lane):
    lane.goto("/start")
    lane.one(LocatorDescriptor(role="button", name="Save"))
    lane.act(ActionKind.CLICK, lane.one(LocatorDescriptor(role="link", name="Next")))
    lane.act(ActionKind.FILL, lane.one(EMAIL), "typed-text")
    assert lane.field().value == "typed-text"


def test_a_candidate_from_before_a_navigation_is_locator_not_found_and_a_fresh_locate_works(lane):
    lane.goto("/login")
    stale = lane.one(EMAIL)
    lane.goto("/home")
    with pytest.raises(LocatorNotFound) as err:
        lane.act(ActionKind.CLICK, stale)
    assert err.value.recoverable
    lane.goto("/login")
    fresh = lane.one(EMAIL)
    assert fresh.candidate_ref != stale.candidate_ref
    lane.act(ActionKind.FILL, fresh, "typed-text")


def test_a_candidate_is_never_acted_on_a_same_looking_element_of_a_reloaded_document(lane):
    lane.goto("/login")
    stale = lane.one(EMAIL)
    lane.goto("/login")                                    # the same URL: a new document with an identical Email field
    with pytest.raises(LocatorNotFound):
        lane.act(ActionKind.FILL, stale, "must-not-land")
    assert lane.field().value == ""
    fresh = lane.one(EMAIL)
    lane.act(ActionKind.FILL, fresh, "lands")
    assert lane.field().value == "lands"


def session_of(lane):
    return lane.adapter._sessions[lane.handle.session_id].ds


def test_a_ref_is_never_issued_twice_so_an_old_one_cannot_name_a_new_element(lane):
    for _ in range(3):
        lane.goto("/login")
        lane.one(EMAIL)
    handles = session_of(lane)._inner._handles
    assert sorted(handles) == ["e3"]                       # e1 and e2 were forgotten with their documents and not reused


def test_a_stale_ref_is_detached_at_the_driver_for_inspect_read_and_perform_never_a_crash(lane):
    lane.goto("/login")
    ds = session_of(lane)
    (info,) = ds.query(ElementQuery(role="textbox", name="Email"))
    lane.goto("/home")
    for use in (lambda: ds.inspect(info.ref), lambda: ds.read(info.ref), lambda: ds.perform(info.ref, "fill", "x", 1000)):
        with pytest.raises(DriverFault) as err:
            use()
        assert err.value.kind is FaultKind.DETACHED
    assert ds._inner._handles == {}


def test_a_closed_session_is_a_session_fault_not_a_stale_element(lane):
    lane.goto("/login")
    stale = lane.one(EMAIL)
    lane.api.world.session_closed = True                   # the browser went away: nothing about the element can be said
    with pytest.raises(SessionLost):
        lane.act(ActionKind.FILL, stale, "x")
