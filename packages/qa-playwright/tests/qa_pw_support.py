# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Builders shared by the adapter tests: a world (fake site, fake driver, redactor, blob sink, adapter), runtime-built
canaries (no credential-shaped literal is written in this repository), and record helpers."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from qa_playwright import AdapterConfig, EgressProfile, PlaywrightAdapter
from qa_playwright.testing.fake import FakeBrowserDriver, FakeClock, FakeElement, FakePage, FakeSite

from agent_harness.qa.blobs import MemoryBlobSink
from agent_harness.qa.egress import AllowEntry, EgressPolicy, StaticResolver
from agent_harness.qa.records import (Action, ActionKind, ActionRequest, AssertionSubject, LocateMode, LocatorDescriptor,
                                      ResolvedTarget, LocatorStrategy, SessionProfile, SubjectKind)
from agent_harness.qa.redaction import PatternRedactor, RedactionConfig

APP = "http://app.test"
PUBLIC_IP = "93.184.216.34"
PROFILE_ID = "egress-main"


def canary(tag: str = "a") -> str:
    """A canary secret built at run time (never written as a literal)."""
    return "".join(["RDQA", "-CANARY-", hashlib.sha256(tag.encode()).hexdigest()[:20]])


def rcv1(tag: str = "d") -> str:
    return "rcv1:" + hashlib.sha256(tag.encode()).hexdigest()


def default_policy(*extra: str) -> EgressPolicy:
    entries: List[AllowEntry] = list(AllowEntry.parse("http://app.test:80"))
    for text in extra:
        entries.extend(AllowEntry.parse(text))
    return EgressPolicy(entries=tuple(entries))


def default_resolver() -> StaticResolver:
    return StaticResolver({"app.test": [PUBLIC_IP], "cdn.test": [PUBLIC_IP], "other.test": [PUBLIC_IP]})


@dataclass
class World:
    site: FakeSite
    clock: FakeClock
    driver: FakeBrowserDriver
    redactor: PatternRedactor
    blobs: MemoryBlobSink
    adapter: PlaywrightAdapter
    canary: str
    profile: SessionProfile

    def open(self, **overrides):
        return self.adapter.open_session(self.profile if not overrides else SessionProfile(
            egress_profile=PROFILE_ID, redaction_policy_id=self.redactor.policy_id, **overrides))

    def session(self):
        return self.driver.sessions[max(self.driver.sessions, key=lambda k: int(k.split("-")[1]))]


def make_world(page: Optional[FakePage] = None, *, adapter_cls: Any = PlaywrightAdapter, redactor_config: Optional[RedactionConfig] = None,
               config: Optional[AdapterConfig] = None, policy: Optional[EgressPolicy] = None, **adapter_kwargs: Any) -> World:
    clock = FakeClock()
    site = FakeSite()
    if page is not None:
        site.add(page)
    driver = FakeBrowserDriver(site, clock)
    secret = canary()
    cfg = redactor_config or RedactionConfig(denylist=(secret,), acknowledged_unredacted_media=("image/png",))
    redactor = PatternRedactor(cfg)
    blobs = MemoryBlobSink()
    profile = EgressProfile(PROFILE_ID, policy if policy is not None else default_policy(), default_resolver())
    adapter = adapter_cls(driver, blobs=blobs, redactor=redactor, clock=clock,
                                egress_profiles={PROFILE_ID: profile}, config=config, **adapter_kwargs)
    sp = SessionProfile(egress_profile=PROFILE_ID, redaction_policy_id=redactor.policy_id)
    return World(site, clock, driver, redactor, blobs, adapter, secret, sp)


def login_page() -> FakePage:
    return FakePage(url=f"{APP}/login", title="Sign in", elements=[
        FakeElement(role="heading", name="Sign in", text="Sign in"),
        FakeElement(role="textbox", name="Email", label="Email", test_id="email", kind="input", value=""),
        FakeElement(role="textbox", name="Password", label="Password", test_id="password", kind="input", value="",
                    sensitive=True),
        FakeElement(role="button", name="Submit", test_id="submit", text="Submit"),
        FakeElement(role="checkbox", name="Remember me", kind="checkbox"),
    ])


def desc(role: Optional[str] = None, name: Optional[str] = None, **kw: Any) -> LocatorDescriptor:
    return LocatorDescriptor(role=role, name=name, **kw)


def request(kind: ActionKind, *, value: Optional[str] = None, step: str = "step-1", key: str = "key-1",
            ref: Optional[str] = None, secret_ref: Any = None) -> ActionRequest:
    return ActionRequest(action=Action(kind=kind, value=value, secret_ref=secret_ref), idempotency_key=key,
                         policy_decision_ref=ref or rcv1("decision"), step_id=step)


def locate_one(world: World, handle: Any, descriptor: LocatorDescriptor, mode: LocateMode = LocateMode.EXACT) -> ResolvedTarget:
    result = world.adapter.locate(handle, descriptor, mode=mode)
    assert len(result.candidates) == 1, result
    return ResolvedTarget(candidate_ref=result.candidates[0].candidate_ref, locator=descriptor,
                          strategy=LocatorStrategy.AUTHORED)


def element_subject(descriptor: LocatorDescriptor, *alternates: LocatorDescriptor) -> AssertionSubject:
    return AssertionSubject(kind=SubjectKind.UI_ELEMENT, locator=descriptor, subject_alternates=tuple(alternates))
