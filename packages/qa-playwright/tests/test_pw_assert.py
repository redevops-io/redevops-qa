# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""assert_ reads and reports a subject; it has no expected value and no verdict. The predicate is the verifier's."""
import pytest
from agent_harness.qa.errors import SessionLost, UnsupportedOperation
from agent_harness.qa.receipts import json_value_digest
from agent_harness.qa.records import (AssertionSubject, ObservedValue, Predicate, PredicateOp, Resolution, SubjectKind,
                                      ResourceRef, ResourceKind)
from agent_harness.qa.verifier import evaluate_predicate
from qa_playwright import AdapterConfig
from qa_playwright.testing.fake import FakeElement, FakePage

from qa_pw_support import APP, canary, desc, element_subject, login_page, make_world


def opened(page=None, **kw):
    w = make_world(page or login_page(), **kw)
    h = w.open()
    w.driver.sessions[h.session_id]._load(page.url if page else f"{APP}/login")
    return w, h


def heading_page(*extra):
    return FakePage(url=f"{APP}/home", elements=[FakeElement(role="heading", name="Welcome", text="  Welcome,\n  Ada  "), *extra])


def test_a_unique_visible_element_resolves_with_its_whitespace_normalised_text_and_a_digest():
    w, h = opened(heading_page())
    out = w.adapter.assert_(h, element_subject(desc("heading", "Welcome")))
    assert type(out) is ObservedValue
    assert (out.resolution, out.match_count, out.value) == (Resolution.RESOLVED, 1, "Welcome, Ada")
    assert out.value_digest == json_value_digest("Welcome, Ada")


def test_the_adapter_returns_only_what_it_observed_the_predicate_is_evaluated_elsewhere():
    w, h = opened(heading_page())
    out = w.adapter.assert_(h, element_subject(desc("heading", "Welcome")))
    assert evaluate_predicate(Predicate(op=PredicateOp.EQUALS, expected="Welcome, Ada"), out)[0].value == "PASS"
    assert evaluate_predicate(Predicate(op=PredicateOp.EQUALS, expected="Goodbye"), out)[0].value == "FAIL"
    assert evaluate_predicate(Predicate(op=PredicateOp.CONTAINS, expected="Ada"), out)[0].value == "PASS"
    # the same observed value serves any predicate: nothing in it depends on what was expected
    assert out == w.adapter.assert_(h, element_subject(desc("heading", "Welcome")))


def test_two_visible_matches_are_ambiguous_with_no_value_and_never_the_first():
    w, h = opened(heading_page(FakeElement(role="heading", name="Welcome", text="Other")))
    out = w.adapter.assert_(h, element_subject(desc("heading", "Welcome")))
    assert (out.resolution, out.match_count, out.value, out.value_digest) == (Resolution.AMBIGUOUS, 2, None, None)
    assert evaluate_predicate(Predicate(op=PredicateOp.EXISTS), out)[1] == "SUBJECT_AMBIGUOUS"


def test_no_match_is_unresolved_after_the_bounded_wait_and_is_indeterminate_for_every_operator():
    w, h = opened(heading_page())
    start = w.clock.ms
    out = w.adapter.assert_(h, element_subject(desc("heading", "Missing")))
    assert (out.resolution, out.match_count, out.value) == (Resolution.UNRESOLVED, 0, None)
    assert 2000 <= w.clock.ms - start < 2200
    for op in (PredicateOp.EXISTS, PredicateOp.ABSENT, PredicateOp.EQUALS):
        verdict, reason = evaluate_predicate(Predicate(op=op, expected="x"), out)
        assert verdict.value == "INDETERMINATE" and reason == "SUBJECT_UNRESOLVED"


def test_a_hidden_element_does_not_count_and_one_visible_among_hidden_duplicates_is_unique():
    page = heading_page(FakeElement(role="heading", name="Welcome", text="Hidden twin", visible_after_ms=10**7))
    w, h = opened(page)
    out = w.adapter.assert_(h, element_subject(desc("heading", "Welcome")))
    assert out.resolution is Resolution.RESOLVED and out.value == "Welcome, Ada"
    only_hidden = FakePage(url=f"{APP}/h", elements=[FakeElement(role="alert", name="Err", text="bad", visible_after_ms=10**7)])
    w2, h2 = opened(only_hidden)
    assert w2.adapter.assert_(h2, element_subject(desc("alert", "Err"))).resolution is Resolution.UNRESOLVED


def test_only_the_alternates_listed_in_the_subject_are_tried_and_in_order_never_a_healed_locator():
    page = FakePage(url=f"{APP}/p", elements=[FakeElement(role="button", name="Save changes", text="Save changes")])
    w, h = opened(page)
    primary = desc("button", "Save")
    out = w.adapter.assert_(h, element_subject(primary))
    assert out.resolution is Resolution.UNRESOLVED                      # "Save changes" is not "Save": not healed
    out2 = w.adapter.assert_(h, element_subject(primary, desc("button", "Save changes")))
    assert out2.resolution is Resolution.RESOLVED and out2.value == "Save changes"


def test_an_ambiguous_primary_is_not_rescued_by_an_alternate():
    page = FakePage(url=f"{APP}/p", elements=[FakeElement(role="button", name="Go", text="a"), FakeElement(role="button", name="Go", text="b"),
                                              FakeElement(role="link", name="Go home", text="c")])
    w, h = opened(page)
    out = w.adapter.assert_(h, element_subject(desc("button", "Go"), desc("link", "Go home")))
    assert out.resolution is Resolution.AMBIGUOUS and out.match_count == 2


def test_form_controls_report_their_value_and_checkboxes_a_boolean():
    w, h = opened()
    sess = w.driver.sessions[h.session_id]
    [e for e in sess.page.elements if e.name == "Email"][0].value = "a@b.test"
    box = [e for e in sess.page.elements if e.kind == "checkbox"][0]
    assert w.adapter.assert_(h, element_subject(desc("checkbox", "Remember me"))).value is False
    box.checked = True
    assert w.adapter.assert_(h, element_subject(desc("checkbox", "Remember me"))).value is True


def test_a_value_the_redactor_changed_is_withheld_so_it_can_neither_pass_nor_fail_by_accident():
    w, h = opened()
    sess = w.driver.sessions[h.session_id]
    [e for e in sess.page.elements if e.name == "Email"][0].value = "alice@example.test"
    out = w.adapter.assert_(h, element_subject(desc("textbox", "Email")))
    assert out.resolution is Resolution.RESOLVED and out.value is None and out.value_digest is not None
    assert "alice@example.test" not in repr(out.to_json())
    assert evaluate_predicate(Predicate(op=PredicateOp.EQUALS, expected="alice@example.test"), out)[1] == "ACTUAL_NOT_COMPARABLE"
    assert evaluate_predicate(Predicate(op=PredicateOp.ABSENT), out)[0].value == "FAIL"      # it is there


def test_a_canary_value_is_never_returned():
    w, h = opened()
    [e for e in w.driver.sessions[h.session_id].page.elements if e.name == "Email"][0].value = w.canary
    out = w.adapter.assert_(h, element_subject(desc("textbox", "Email")))
    assert out.value is None and w.canary not in repr(out.to_json())


def test_a_password_field_is_resolved_but_its_value_is_never_read_into_the_result():
    w, h = opened()
    [e for e in w.driver.sessions[h.session_id].page.elements if e.name == "Password"][0].value = "pw-" + canary("p")
    out = w.adapter.assert_(h, element_subject(desc("textbox", "Password")))
    assert out.resolution is Resolution.RESOLVED and out.value is None
    assert out.value_digest == json_value_digest("[withheld:sensitive]")
    assert canary("p") not in repr(out.to_json())


def test_an_over_long_value_is_withheld_with_a_constant_digest():
    page = FakePage(url=f"{APP}/p", elements=[FakeElement(role="paragraph", name="long", text="w" * 9000)])
    w, h = opened(page)
    out = w.adapter.assert_(h, element_subject(desc("paragraph", "long")))
    assert out.value is None and out.value_digest == json_value_digest("[withheld:oversize]")


def test_the_url_subject_reports_the_current_url_and_withholds_a_url_the_redactor_changed():
    w, h = opened()
    out = w.adapter.assert_(h, AssertionSubject(kind=SubjectKind.URL))
    assert out.value == f"{APP}/login" and out.resolution is Resolution.RESOLVED
    page = login_page()
    page.url = f"{APP}/login?access_token=" + "q" * 30
    w2, h2 = opened(page)
    out2 = w2.adapter.assert_(h2, AssertionSubject(kind=SubjectKind.URL, pattern="^http://app.test/login"))
    assert out2.value is None and out2.value_digest is not None and "q" * 30 not in repr(out2.to_json())


def test_a_response_subject_reports_the_status_of_the_one_matching_response():
    page = login_page()
    page.subresources += [(f"{APP}/api/session?x=1", "fetch")]
    w, h = opened(page)
    out = w.adapter.assert_(h, AssertionSubject(kind=SubjectKind.RESPONSE, pattern=r"/api/session$"))
    assert (out.resolution, out.match_count, out.value) == (Resolution.RESOLVED, 1, 200)


def test_response_subject_none_one_many_and_lost_events():
    page = login_page()
    page.subresources += [(f"{APP}/api/a", "fetch"), (f"{APP}/api/b", "fetch")]
    w, h = opened(page)
    assert w.adapter.assert_(h, AssertionSubject(kind=SubjectKind.RESPONSE, pattern="/nothing")).resolution is Resolution.UNRESOLVED
    many = w.adapter.assert_(h, AssertionSubject(kind=SubjectKind.RESPONSE, pattern="/api/"))
    assert many.resolution is Resolution.AMBIGUOUS and many.match_count == 2
    w.driver.sessions[h.session_id].dropped["network"] = 3
    assert w.adapter.assert_(h, AssertionSubject(kind=SubjectKind.RESPONSE, pattern="/api/a")).resolution is Resolution.UNRESOLVED


def test_a_blocked_or_failed_request_is_not_a_response():
    page = login_page()
    page.subresources += [("http://evil.test/api/x", "fetch")]
    w, h = opened(page)
    assert w.adapter.assert_(h, AssertionSubject(kind=SubjectKind.RESPONSE, pattern="/api/x")).resolution is Resolution.UNRESOLVED


def test_malformed_subjects_are_unsupported_operations():
    w, h = opened()
    for subject in (AssertionSubject(kind=SubjectKind.UI_ELEMENT), AssertionSubject(kind=SubjectKind.RESPONSE),
                    AssertionSubject(kind=SubjectKind.RESPONSE, pattern="("),
                    AssertionSubject(kind=SubjectKind.RESOURCE_INPUTS,
                                     inputs=(ResourceRef(kind=ResourceKind.MANIFEST_PATH, path="a.yaml"),)), "x"):
        with pytest.raises(UnsupportedOperation):
            w.adapter.assert_(h, subject)


def test_assert_does_not_change_the_page():
    w, h = opened()
    sess = w.driver.sessions[h.session_id]
    snap = (sess.accessibility_snapshot(), tuple(sess.typed), tuple(e.value for e in sess.page.elements))
    w.adapter.assert_(h, element_subject(desc("heading", "Sign in")))
    w.adapter.assert_(h, AssertionSubject(kind=SubjectKind.URL))
    assert (sess.accessibility_snapshot(), tuple(sess.typed), tuple(e.value for e in sess.page.elements)) == snap


def test_assert_on_a_lost_session_is_session_lost():
    w, h = opened()
    w.driver.lose(h.session_id)
    with pytest.raises(SessionLost):
        w.adapter.assert_(h, element_subject(desc("heading", "Sign in")))
