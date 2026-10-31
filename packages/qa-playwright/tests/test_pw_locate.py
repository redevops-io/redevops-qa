# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""locate: every candidate, a uniqueness flag, role/label/test-id first, auto-wait on the injected clock, no side effects."""
import pytest
from agent_harness.qa.errors import SessionLost, UnsupportedOperation
from agent_harness.qa.records import LocateMode, LocatorDescriptor
from qa_playwright import AdapterConfig
from qa_playwright.testing.fake import FakeElement, FakePage

from qa_pw_support import APP, desc, login_page, make_world


def page_with(*elements):
    return FakePage(url=f"{APP}/p", elements=list(elements))


def btn(name, **kw):
    return FakeElement(role="button", name=name, text=name, **kw)


def test_one_match_is_unique_and_carries_role_name_visibility_and_enabled_state():
    w = make_world(login_page())
    h = w.open()
    w.driver.sessions[h.session_id]._load(f"{APP}/login")
    result = w.adapter.locate(h, desc("button", "Submit"), mode=LocateMode.EXACT)
    (c,) = result.candidates
    assert (c.role, c.name, c.visible, c.enabled, c.unique) == ("button", "Submit", True, True, True)
    assert c.candidate_ref.startswith("cand-")


def test_several_matches_are_all_returned_none_unique_in_document_order():
    w = make_world(page_with(btn("Save"), btn("Save"), btn("Save"), btn("Cancel")))
    h = w.open()
    w.driver.sessions[h.session_id]._load(f"{APP}/p")
    result = w.adapter.locate(h, desc("button", "Save"), mode=LocateMode.EXACT)
    assert len(result.candidates) == 3 and not any(c.unique for c in result.candidates)
    assert len({c.candidate_ref for c in result.candidates}) == 3


def test_zero_matches_is_an_empty_result_not_an_error_and_only_after_the_wait():
    w = make_world(page_with(btn("Save")))
    h = w.open()
    w.driver.sessions[h.session_id]._load(f"{APP}/p")
    before = w.clock.ms
    result = w.adapter.locate(h, desc("button", "Delete"), mode=LocateMode.EXACT)
    assert result.candidates == ()
    assert 2000 <= w.clock.ms - before <= 2100            # the locate timeout, on the injected clock


def test_an_element_that_appears_within_the_timeout_is_found_by_the_auto_wait():
    w = make_world(page_with(btn("Late", visible_after_ms=0)))
    h = w.open()
    sess = w.driver.sessions[h.session_id]
    sess._load(f"{APP}/p")
    sess.page.elements.append(FakeElement(role="button", name="Later", key="late-1"))
    result = w.adapter.locate(h, desc("button", "Later"), mode=LocateMode.EXACT)
    assert len(result.candidates) == 1


def test_a_hidden_element_is_returned_flagged_not_visible_and_a_disabled_one_flagged_not_enabled():
    w = make_world(page_with(btn("Hidden", visible_after_ms=10**6), btn("Off", enabled_after_ms=10**6)))
    h = w.open()
    w.driver.sessions[h.session_id]._load(f"{APP}/p")
    hidden = w.adapter.locate(h, desc("button", "Hidden"), mode=LocateMode.EXACT).candidates[0]
    off = w.adapter.locate(h, desc("button", "Off"), mode=LocateMode.EXACT).candidates[0]
    assert (hidden.visible, hidden.enabled) == (False, True)
    assert (off.visible, off.enabled) == (True, False)


@pytest.mark.parametrize("descriptor", [desc("textbox", "Email"), LocatorDescriptor(label="Email"),
                                       LocatorDescriptor(test_id="email"), LocatorDescriptor(role="textbox", label="Email"),
                                       LocatorDescriptor(role="textbox", test_id="email", name="Email")])
def test_role_label_and_test_id_locators_resolve_the_same_element(descriptor):
    w = make_world(login_page())
    h = w.open()
    w.driver.sessions[h.session_id]._load(f"{APP}/login")
    result = w.adapter.locate(h, descriptor, mode=LocateMode.EXACT)
    assert [c.name for c in result.candidates] == ["Email"]


def test_exact_mode_is_equality_and_semantic_mode_is_a_case_insensitive_substring():
    w = make_world(login_page())
    h = w.open()
    w.driver.sessions[h.session_id]._load(f"{APP}/login")
    assert w.adapter.locate(h, desc("button", "sub"), mode=LocateMode.EXACT).candidates == ()
    semantic = w.adapter.locate(h, desc("button", "sub"), mode=LocateMode.SEMANTIC)
    assert [c.name for c in semantic.candidates] == ["Submit"]


def test_text_hint_is_used_only_in_semantic_mode():
    w = make_world(login_page())
    h = w.open()
    w.driver.sessions[h.session_id]._load(f"{APP}/login")
    hint = LocatorDescriptor(role="button", text_hint="subm")
    assert w.adapter.locate(h, hint, mode=LocateMode.SEMANTIC).candidates[0].name == "Submit"
    with pytest.raises(UnsupportedOperation):
        # exact mode ignores the hint: a hint alone is nothing to match on, never a way to pick an element
        w.adapter.locate(h, LocatorDescriptor(text_hint="subm"), mode=LocateMode.EXACT)


def test_a_descriptor_with_nothing_to_match_on_is_refused_and_never_means_everything():
    w = make_world(login_page())
    h = w.open()
    with pytest.raises(UnsupportedOperation):
        w.adapter.locate(h, LocatorDescriptor(), mode=LocateMode.EXACT)
    with pytest.raises(UnsupportedOperation):
        w.adapter.locate(h, LocatorDescriptor(text_hint="x"), mode=LocateMode.EXACT)


def test_frames_are_part_of_the_locator():
    w = make_world(page_with(FakeElement(role="button", name="Pay", frame=("checkout",)), btn("Pay")))
    h = w.open()
    w.driver.sessions[h.session_id]._load(f"{APP}/p")
    main = w.adapter.locate(h, desc("button", "Pay"), mode=LocateMode.EXACT)
    framed = w.adapter.locate(h, LocatorDescriptor(role="button", name="Pay", frame_path=("checkout",)), mode=LocateMode.EXACT)
    assert len(main.candidates) == 1 and len(framed.candidates) == 1
    assert main.candidates[0].candidate_ref != framed.candidates[0].candidate_ref


def test_candidate_count_is_capped_and_none_is_unique_then():
    w = make_world(page_with(*[btn("Dup") for _ in range(8)]), config=AdapterConfig(max_candidates=3))
    h = w.open()
    w.driver.sessions[h.session_id]._load(f"{APP}/p")
    result = w.adapter.locate(h, desc("button", "Dup"), mode=LocateMode.EXACT)
    assert len(result.candidates) == 3 and not any(c.unique for c in result.candidates)


def test_locate_has_no_side_effects_on_the_page():
    w = make_world(login_page())
    h = w.open()
    sess = w.driver.sessions[h.session_id]
    sess._load(f"{APP}/login")
    snapshot = (sess.accessibility_snapshot(), list(sess.typed), len(sess.network))
    w.adapter.locate(h, desc("button", "Submit"), mode=LocateMode.EXACT)
    assert (sess.accessibility_snapshot(), list(sess.typed), len(sess.network)) == snapshot


def test_the_candidate_table_is_bounded():
    w = make_world(page_with(btn("One")), config=AdapterConfig(max_candidate_table=5))
    h = w.open()
    w.driver.sessions[h.session_id]._load(f"{APP}/p")
    refs = [w.adapter.locate(h, desc("button", "One"), mode=LocateMode.EXACT).candidates[0].candidate_ref for _ in range(9)]
    assert len(set(refs)) == 9
    assert len(w.adapter._sessions[h.session_id].cands) == 5


def test_locate_on_a_lost_session_is_session_lost():
    w = make_world(login_page())
    h = w.open()
    w.driver.lose(h.session_id)
    with pytest.raises(SessionLost):
        w.adapter.locate(h, desc("button", "Submit"), mode=LocateMode.EXACT)
