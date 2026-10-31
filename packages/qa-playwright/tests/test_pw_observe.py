# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""observe and capture: what is in an observation, that everything is redacted first, and that nothing raw is ever stored."""
import json

import pytest
from agent_harness.qa.blobs import MemoryBlobSink, digest_of_bytes
from agent_harness.qa.errors import (RedactionFailed, ResourceLimitExceeded, SessionLost, UnsupportedOperation)
from agent_harness.qa.receipts import state_hash
from agent_harness.qa.records import CaptureKind, Observation, ObserveRequest, Phase, SessionProfile
from agent_harness.qa.redaction import RedactionConfig
from qa_playwright import AdapterConfig, EgressProfile, PlaywrightAdapter
from qa_playwright.testing.fake import FakeBrowserDriver, FakeClock, FakeElement, FakeSite

from qa_pw_support import APP, PROFILE_ID, canary, default_policy, default_resolver, login_page, make_world


def opened(page=None, **kw):
    w = make_world(page or login_page(), **kw)
    h = w.open()
    w.driver.sessions[h.session_id]._load(page.url if page else f"{APP}/login")
    return w, h


def observe(w, h, *kinds, step="step-1", phase=Phase.BEFORE):
    return w.adapter.observe(h, ObserveRequest(phase=phase, step_id=step, capture=tuple(kinds)))


def test_the_default_observation_has_url_frame_dom_meta_snapshot_and_screenshot_and_is_marked_redacted():
    w, h = opened()
    obs = observe(w, h)
    assert type(obs) is Observation
    assert obs.url == f"{APP}/login" and obs.frame == "main" and obs.redaction_applied
    assert obs.redaction_policy_id == w.redactor.policy_id
    assert obs.a11y_snapshot_ref and obs.screenshot_ref and obs.dom_meta
    assert obs.console_excerpt_ref is None and obs.network_excerpt_ref is None
    assert obs.source.adapter == "qa-playwright" and obs.source.browser == "fake-chromium"
    assert obs.step_id == "step-1" and obs.phase is Phase.BEFORE
    assert dict(obs.dom_meta)["title"] == "Sign in" and dict(obs.dom_meta)["inputs"] == 3


def test_requested_kinds_are_exactly_what_is_returned_and_excerpts_are_available_on_request():
    w, h = opened()
    obs = observe(w, h, CaptureKind.CONSOLE_EXCERPT, CaptureKind.NETWORK_EXCERPT)
    assert obs.console_excerpt_ref and obs.network_excerpt_ref
    assert obs.a11y_snapshot_ref is None and obs.screenshot_ref is None and obs.dom_meta is None
    net = json.loads(w.blobs.get(obs.network_excerpt_ref.content_hash))
    assert net["entries"][0]["status"] == 200 and net["entries"][0]["resource_type"] == "document"


def test_trace_is_not_an_observation_kind():
    w, h = opened()
    with pytest.raises(UnsupportedOperation):
        observe(w, h, CaptureKind.TRACE)


def test_every_reference_is_a_full_width_digest_of_exactly_the_stored_redacted_bytes():
    w, h = opened()
    obs = observe(w, h)
    for ref in (obs.a11y_snapshot_ref, obs.screenshot_ref):
        assert ref.ref == ref.content_hash and len(ref.content_hash) == len("sha256:") + 64
        assert digest_of_bytes(w.blobs.get(ref.content_hash)) == ref.content_hash
    assert obs.screenshot_ref.media_type == "image/png" and obs.screenshot_ref.modality == "image"


def test_the_state_hash_is_stable_for_an_unchanged_page_and_changes_when_the_page_changes():
    w, h = opened()
    a, b = observe(w, h, step="s1"), observe(w, h, step="s2", phase=Phase.AFTER)
    assert a.observation_id != b.observation_id and state_hash(a) == state_hash(b)
    w.driver.sessions[h.session_id].page.elements.append(FakeElement(role="alert", name="Oops", text="Oops"))
    assert state_hash(observe(w, h)) != state_hash(a)


def test_a_canary_in_the_page_reaches_no_observation_blob_or_metadata():
    page = login_page()
    secret = canary()
    page.title = f"Welcome {secret}"
    page.elements.append(FakeElement(role="paragraph", name="note", text=f"token {secret}"))
    page.console.append(("log", f"debug {secret}"))
    page.subresources.append((f"{APP}/api?session_id={secret}", "fetch"))
    page.url = f"{APP}/login?token={secret}"
    w = make_world(page)
    h = w.open()
    w.driver.sessions[h.session_id]._load(page.url)
    obs = observe(w, h, CaptureKind.A11Y_SNAPSHOT, CaptureKind.DOM_META, CaptureKind.CONSOLE_EXCERPT,
                  CaptureKind.NETWORK_EXCERPT)
    assert secret not in json.dumps(obs.to_json())
    for digest in w.blobs.digests():
        assert secret.encode() not in w.blobs.get(digest)
    assert secret not in repr(w.adapter.capture(h, [CaptureKind.A11Y_SNAPSHOT]))


def test_an_email_and_a_bearer_value_are_redacted_by_the_default_policy_before_storage():
    page = login_page()
    page.elements.append(FakeElement(role="paragraph", name="n",
                                     text="mail alice@example.test and Authorization: Bearer " + canary("bearer")))
    w, h = opened(page)
    obs = observe(w, h, CaptureKind.A11Y_SNAPSHOT)
    stored = w.blobs.get(obs.a11y_snapshot_ref.content_hash).decode()
    assert "alice@example.test" not in stored and canary("bearer") not in stored and "[REDACTED:" in stored


def test_a_redactor_that_refuses_an_image_drops_the_screenshot_with_redaction_failed_and_stores_nothing():
    w = make_world(login_page(), redactor_config=RedactionConfig())      # the stock policy does not accept image/png
    h = w.open()
    w.driver.sessions[h.session_id]._load(f"{APP}/login")
    with pytest.raises(RedactionFailed) as err:
        observe(w, h, CaptureKind.SCREENSHOT)
    assert err.value.details["reason"] == "UNSUPPORTED_MEDIA_TYPE" and len(w.blobs) == 0
    obs = observe(w, h, CaptureKind.A11Y_SNAPSHOT, CaptureKind.DOM_META)        # text kinds still work
    assert obs.a11y_snapshot_ref and obs.screenshot_ref is None


class Exploding:
    policy_id = "rcv1:" + "1" * 64

    def redact(self, data, media_type):
        raise RuntimeError("redactor internals: " + data[:20].decode("latin-1"))


class Unstable(Exploding):
    def redact(self, data, media_type):
        return "not bytes"


@pytest.mark.parametrize("redactor_cls", [Exploding, Unstable])
def test_any_failing_or_unusable_redaction_hook_is_redaction_failed_with_no_raw_text_in_the_error(redactor_cls):
    clock, site = FakeClock(), FakeSite()
    site.add(login_page())
    redactor = redactor_cls()
    adapter = PlaywrightAdapter(FakeBrowserDriver(site, clock), blobs=MemoryBlobSink(), redactor=redactor, clock=clock,
                                egress_profiles={PROFILE_ID: EgressProfile(PROFILE_ID, default_policy(), default_resolver())})
    h = adapter.open_session(SessionProfile(egress_profile=PROFILE_ID, redaction_policy_id=redactor.policy_id))
    adapter._driver.sessions[h.session_id]._load(f"{APP}/login")
    with pytest.raises(RedactionFailed) as err:
        adapter.observe(h, ObserveRequest(phase=Phase.BEFORE, step_id="s", capture=(CaptureKind.A11Y_SNAPSHOT,)))
    assert "Sign in" not in str(err.value) and "Sign in" not in repr(err.value.details)


def test_nothing_reaches_the_blob_sink_except_redacted_output():
    class Spy(MemoryBlobSink):
        def __init__(self):
            super().__init__()
            self.puts = []

        def put(self, data, media_type):
            self.puts.append((bytes(data), media_type))
            return super().put(data, media_type)
    page = login_page()
    page.elements.append(FakeElement(role="paragraph", name="n", text="contact bob@example.test"))
    w = make_world(page)
    w.blobs = w.adapter._blobs = Spy()
    h = w.open()
    w.driver.sessions[h.session_id]._load(page.url)
    observe(w, h, CaptureKind.A11Y_SNAPSHOT, CaptureKind.SCREENSHOT, CaptureKind.DOM_META)
    w.adapter.capture(h, [CaptureKind.CONSOLE_EXCERPT])
    assert w.blobs.puts and all(b"bob@example.test" not in data for data, _ in w.blobs.puts)


def test_an_oversize_raw_artifact_is_refused_whole_never_cut_before_redaction():
    page = login_page()
    page.elements.append(FakeElement(role="paragraph", name="n", text="x" * 5000))
    w, h = opened(page, config=AdapterConfig(max_raw_artifact_bytes=2000))
    with pytest.raises(ResourceLimitExceeded):
        observe(w, h, CaptureKind.A11Y_SNAPSHOT)


def test_excerpts_are_bounded_by_count_and_entry_length_after_redaction_and_report_drops():
    page = login_page()
    page.console.extend(("log", f"line {i} " + "y" * 900) for i in range(80))
    w, h = opened(page, config=AdapterConfig(max_excerpt_entries=10, max_excerpt_text_chars=100))
    obs = observe(w, h, CaptureKind.CONSOLE_EXCERPT)
    doc = json.loads(w.blobs.get(obs.console_excerpt_ref.content_hash))
    assert len(doc["entries"]) == 10 and doc["dropped"] == 70
    assert all(len(e["text"]) <= 100 for e in doc["entries"]) and doc["entries"][-1]["text"].startswith("line 79")


def test_the_dom_meta_title_is_bounded_and_dom_meta_stays_inside_the_record_bound():
    page = login_page()
    page.title = "T" * 5000
    w, h = opened(page)
    meta = dict(observe(w, h, CaptureKind.DOM_META).dom_meta)
    assert len(meta["title"]) <= 200 and len(json.dumps(meta).encode()) <= 4096


def test_a_url_with_a_secret_in_its_query_is_redacted_in_the_observation():
    page = login_page()
    page.url = f"{APP}/login?access_token=" + "z" * 30
    w, h = opened(page)
    obs = observe(w, h, CaptureKind.DOM_META)
    assert "z" * 30 not in obs.url and obs.url.startswith(f"{APP}/login")


def test_capture_returns_one_reference_per_distinct_kind_in_order_and_dedupes():
    w, h = opened()
    refs = w.adapter.capture(h, [CaptureKind.SCREENSHOT, CaptureKind.A11Y_SNAPSHOT, CaptureKind.SCREENSHOT,
                                 CaptureKind.DOM_META, CaptureKind.NETWORK_EXCERPT, CaptureKind.CONSOLE_EXCERPT])
    assert [r.media_type for r in refs] == ["image/png", "text/plain", "application/json", "application/json",
                                            "application/json"]
    assert all(w.blobs.exists(r.content_hash) for r in refs)
    with pytest.raises(UnsupportedOperation):
        w.adapter.capture(h, ["screenshot"])


def test_a_trace_is_off_by_default_and_when_on_it_is_restricted_and_must_pass_the_redactor():
    w, h = opened()
    with pytest.raises(UnsupportedOperation):
        w.adapter.capture(h, [CaptureKind.TRACE])
    w2 = make_world(login_page(), config=AdapterConfig(allow_trace=True))
    h2 = w2.open()
    assert w2.driver.specs[0].record_trace is True
    with pytest.raises(RedactionFailed):            # the redactor has not acknowledged application/zip: nothing is stored
        w2.adapter.capture(h2, [CaptureKind.TRACE])
    assert len(w2.blobs) == 0
    cfg = RedactionConfig(acknowledged_unredacted_media=("application/zip", "image/png"))
    w3 = make_world(login_page(), redactor_config=cfg, config=AdapterConfig(allow_trace=True))
    h3 = w3.open()
    (ref,) = w3.adapter.capture(h3, [CaptureKind.TRACE])
    assert ref.source == "restricted-trace" and ref.media_type == "application/zip" and w3.blobs.exists(ref.content_hash)


def test_observe_on_a_lost_session_is_session_lost_and_a_bad_request_is_refused():
    w, h = opened()
    with pytest.raises(UnsupportedOperation):
        w.adapter.observe(h, {"phase": "BEFORE"})
    w.driver.lose(h.session_id)
    with pytest.raises(SessionLost):
        observe(w, h)


def test_duration_and_time_come_from_the_injected_clock_only():
    w, h = opened()
    obs = observe(w, h)
    assert obs.observed_at == "2026-01-01T00:00:00Z" and obs.duration_ms == 0
