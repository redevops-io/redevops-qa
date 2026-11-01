# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Element references are scoped to the document they were resolved in, against a real Chromium.

A reference the driver issued for an element of one document must never be compared with, or used against, an element of
another document: after a navigation (by an action or by a click), a reload of the same URL, or across a frame boundary the
next locate must work, and a candidate from before the change must be refused with ``LocatorNotFound`` (never a crash, never
acted on a different element that happens to match the same locator).

Runs in the browser CI job only (it needs Playwright and Chromium and never skips).
"""
import pytest
from agent_harness.qa.errors import LocatorNotFound
from agent_harness.qa.records import ActionKind, AssertionSubject, LocatorDescriptor, SubjectKind

from test_pw_browser_driver import act, build, goto, one

pytestmark = pytest.mark.browser

EMAIL = LocatorDescriptor(role="textbox", name="Email")


def email_value(adapter, handle):
    return adapter.assert_(handle, AssertionSubject(kind=SubjectKind.UI_ELEMENT, locator=EMAIL)).value


@pytest.fixture()
def session(playwright_available, fixture_server):
    adapter, handle = build(fixture_server)
    try:
        yield adapter, handle, fixture_server
    finally:
        adapter.shutdown()


def test_locate_navigate_locate_and_act_works_after_every_navigation(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/login")
    one(adapter, handle, EMAIL)
    goto(adapter, handle, server, "/home")
    one(adapter, handle, LocatorDescriptor(role="heading", name="Welcome"))    # the second locate after a navigation
    goto(adapter, handle, server, "/login")
    act(adapter, handle, ActionKind.FILL, one(adapter, handle, EMAIL), "typed-text")
    assert email_value(adapter, handle) == "typed-text"


def test_locate_works_after_a_click_that_navigates(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/start")
    one(adapter, handle, LocatorDescriptor(role="button", name="Save"))
    act(adapter, handle, ActionKind.CLICK, one(adapter, handle, LocatorDescriptor(role="link", name="Next")))
    act(adapter, handle, ActionKind.FILL, one(adapter, handle, EMAIL), "typed-text")
    assert email_value(adapter, handle) == "typed-text"
    goto(adapter, handle, server, "/start")
    one(adapter, handle, LocatorDescriptor(role="button", name="Save"))


def test_a_candidate_from_before_a_navigation_is_locator_not_found_and_a_fresh_locate_works(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/login")
    stale = one(adapter, handle, EMAIL)
    goto(adapter, handle, server, "/home")
    with pytest.raises(LocatorNotFound) as err:
        act(adapter, handle, ActionKind.CLICK, stale)
    assert err.value.recoverable
    goto(adapter, handle, server, "/login")
    fresh = one(adapter, handle, EMAIL)
    assert fresh.candidate_ref != stale.candidate_ref
    act(adapter, handle, ActionKind.FILL, fresh, "typed-text")


def test_a_candidate_is_never_acted_on_a_same_looking_element_of_a_reloaded_document(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/login")
    stale = one(adapter, handle, EMAIL)
    goto(adapter, handle, server, "/login")                    # the same URL, a new document with an identical Email field
    with pytest.raises(LocatorNotFound):
        act(adapter, handle, ActionKind.FILL, stale, "must-not-land")
    assert email_value(adapter, handle) == ""                  # the new field was not touched
    fresh = one(adapter, handle, EMAIL)
    assert fresh.candidate_ref != stale.candidate_ref
    act(adapter, handle, ActionKind.FILL, fresh, "lands")
    assert email_value(adapter, handle) == "lands"


def test_the_candidate_of_a_click_that_navigated_away_is_locator_not_found(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/start")
    save = one(adapter, handle, LocatorDescriptor(role="button", name="Save"))
    act(adapter, handle, ActionKind.CLICK, one(adapter, handle, LocatorDescriptor(role="link", name="Next")))
    with pytest.raises(LocatorNotFound):
        act(adapter, handle, ActionKind.CLICK, save)


def test_elements_of_the_page_and_of_a_frame_can_both_be_located_and_acted_on(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/frames")
    outer = one(adapter, handle, LocatorDescriptor(role="button", name="Outer"))
    inner_descriptor = LocatorDescriptor(role="button", name="Inner", frame_path=("inner",))
    inner = one(adapter, handle, inner_descriptor)             # a second locate in another document (the frame)
    act(adapter, handle, ActionKind.CLICK, outer)
    act(adapter, handle, ActionKind.CLICK, inner)
    act(adapter, handle, ActionKind.CLICK, one(adapter, handle, LocatorDescriptor(role="button", name="Outer")))


def test_a_candidate_inside_a_frame_is_refused_after_the_frame_navigates(session):
    adapter, handle, server = session
    goto(adapter, handle, server, "/frames")
    descriptor = LocatorDescriptor(role="link", name="Leave", frame_path=("inner",))
    leave = one(adapter, handle, descriptor)
    outer = one(adapter, handle, LocatorDescriptor(role="button", name="Outer"))
    act(adapter, handle, ActionKind.CLICK, leave)              # the frame now shows another document
    with pytest.raises(LocatorNotFound):
        act(adapter, handle, ActionKind.CLICK, leave)
    act(adapter, handle, ActionKind.CLICK, outer)              # the main document is unchanged, its candidate still works
