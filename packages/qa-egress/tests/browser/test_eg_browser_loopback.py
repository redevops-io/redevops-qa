# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Chromium and the egress gateway: loopback and private destinations are NOT bypassed, so the gateway decides them.

What these tests establish, against the pinned Chromium and Playwright:
  1. with the launch configuration of ``qa_egress.launch``, a request to ``127.0.0.1``, to ``localhost`` and to a private-range
     literal reaches the gateway, which logs and decides each (the fixture server sees them only through the gateway);
  2. a metadata address (``169.254.169.254``, ``fd00:ec2::254``, ``metadata.google.internal``) is refused even when the
     operator lists it, and never connected to;
  3. CONTROLS that show the tests can fail: a browser launched with no proxy at all, and one launched with a proxy but without
     the ``<-loopback>`` override, both reach the loopback fixture WITHOUT the gateway seeing anything.

NOT RUN in the environment this file was written in (no Playwright package, no browser, no network). It runs in the browser CI
job only. If the control in (3b) ever fails, the pinned Playwright or Chromium changed how the implicit loopback bypass works
and ``qa_egress.launch`` must be revisited; that is what this lane is for.
"""
import pytest
from agent_harness.qa.blobs import MemoryBlobSink
from agent_harness.qa.clock import SystemClock
from agent_harness.qa.egress import AllowEntry, EgressPolicy
from agent_harness.qa.errors import QAError
from agent_harness.qa.records import (Action, ActionKind, ActionRequest, ObserveRequest, Phase, SessionProfile)
from agent_harness.qa.redaction import PatternRedactor, RedactionConfig
from qa_egress import GatewayServer, build_launch_config, policy_off_config
from qa_playwright import (AdapterConfig, ContextSpec, DriverFault, EgressProfile, FaultKind, PlaywrightAdapter, PlaywrightDriver,
                           ProxySettings)

from qa_eg_support import ScriptedResolver, SpyOpener, Upstream, ok

pytestmark = pytest.mark.browser

PAGE = ('<!doctype html><title>Home</title><h1>Welcome</h1><img src="/pixel.png" alt="p">'
        "<script>fetch('/api/ok').catch(function () {});</script>")
DECISION = "rcv1:" + "cd" * 32


def entry(host, port, net):
    return AllowEntry(host=host, networks=(net,), schemes=("http",), ports=(port,), private_ok=True)


@pytest.fixture()
def lane(playwright_available):
    with Upstream() as fixture:
        fixture.default = ok(PAGE, extra=["Content-Type: text/html; charset=utf-8"])
        port = fixture.port
        policy = EgressPolicy(entries=(
            entry("127.0.0.1", port, "127.0.0.1/32"), entry("localhost", port, "127.0.0.1/32"), entry("10.1.2.3", port, "10.1.2.3/32"),
            # an operator who lists a metadata address by mistake: it must still be refused
            entry("169.254.169.254", port, "169.254.169.254/32"), entry("169.254.169.254", 80, "169.254.169.254/32"),
            entry("fd00:ec2::254", 80, "fd00:ec2::254/128")))
        resolver = ScriptedResolver({"localhost": [["127.0.0.1"]]})
        spy = SpyOpener({"127.0.0.1": port, "10.1.2.3": port})
        server = GatewayServer(policy, resolver, opener=spy)
        with server as gateway:
            driver = PlaywrightDriver()
            try:
                yield type("Lane", (), {"fixture": fixture, "port": port, "policy": policy, "resolver": resolver, "spy": spy,
                                        "gateway": gateway, "driver": driver})
            finally:
                driver.close()


def hosts(events):
    return sorted({e["decision"]["host"] for e in events if "decision" in e and e["request_kind"] != "redirect"})


def raw_session(lane, spec_args, proxy):
    return lane.driver.new_session(ContextSpec(session_id="lane-1", profile_id="lane", launch_args=tuple(spec_args), proxy=proxy,
                                               request_gate=None))


def test_loopback_localhost_and_a_private_literal_all_go_through_the_gateway(lane):
    cfg = build_launch_config("127.0.0.1", lane.gateway.port)
    redactor = PatternRedactor(RedactionConfig(acknowledged_unredacted_media=("image/png",)))
    profile = EgressProfile("lane", lane.policy, lane.resolver, **{"launch_args": cfg.profile_fields()["launch_args"],
                                                                    "proxy": ProxySettings(**cfg.profile_fields()["proxy"])})
    adapter = PlaywrightAdapter(lane.driver, blobs=MemoryBlobSink(), redactor=redactor, clock=SystemClock(),
                                egress_profiles={"lane": profile}, config=AdapterConfig(action_timeout_ms=5000))
    handle = adapter.open_session(SessionProfile(egress_profile="lane", redaction_policy_id=redactor.policy_id))
    try:
        for host in ("127.0.0.1", "localhost", "10.1.2.3"):
            adapter.act(handle, ActionRequest(action=Action(kind=ActionKind.NAVIGATE, value=f"http://{host}:{lane.port}/home"),
                                              idempotency_key="k", policy_decision_ref=DECISION, step_id="s"), None)
            obs = adapter.observe(handle, ObserveRequest(phase=Phase.AFTER, step_id="s"))
            assert dict(obs.dom_meta)["title"] == "Home"
        lane.gateway.wait_idle()
        events = lane.gateway.events()
        assert hosts(events) == ["10.1.2.3", "127.0.0.1", "localhost"]
        assert all(e["decision"]["verdict"] == "ALLOW" for e in events)
        seen_hosts = {s.headers["host"].split(":")[0] for s in lane.fixture.seen}
        assert {"127.0.0.1", "localhost", "10.1.2.3"} <= seen_hosts           # the fixture was reached, through the gateway only
        assert {c[0] for c in lane.spy.calls} == {"127.0.0.1", "10.1.2.3"}      # localhost was pinned to its resolved address
    finally:
        adapter.shutdown()


def test_subresources_and_script_requests_are_decided_by_the_gateway_too(lane):
    cfg = build_launch_config("127.0.0.1", lane.gateway.port)
    session = raw_session(lane, cfg.chromium_args, ProxySettings(**cfg.profile_fields()["proxy"]))
    try:
        session.goto(f"http://127.0.0.1:{lane.port}/home", 8000)
        session.settle(500)
        lane.gateway.wait_idle()
        paths = [s.request_line.split(" ")[1] for s in lane.fixture.seen]
        assert "/pixel.png" in paths and "/api/ok" in paths
        assert len([e for e in lane.gateway.events() if e["decision"]["host"] == "127.0.0.1"]) >= 3
    finally:
        session.close()


@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data/", "http://[fd00:ec2::254]/", "http://metadata.google.internal/",
                                 "https://169.254.169.254/"])
def test_a_metadata_address_is_refused_even_when_it_is_listed_and_is_never_connected_to(lane, url):
    cfg = build_launch_config("127.0.0.1", lane.gateway.port)
    session = raw_session(lane, cfg.chromium_args, ProxySettings(**cfg.profile_fields()["proxy"]))
    try:
        with pytest.raises(DriverFault) as err:
            session.goto(url, 8000)
        assert err.value.kind is FaultKind.NAVIGATION_BLOCKED
        lane.gateway.wait_idle()
        refusals = [e for e in lane.gateway.events() if e["decision"]["verdict"] == "DENY"]
        assert refusals and all(set(e["decision"]["reasons"]) & {"DENY_METADATA_ADDRESS", "DENY_METADATA_NAME"} for e in refusals)
        assert lane.spy.calls == []
    finally:
        session.close()


def test_an_unlisted_origin_and_a_name_the_browser_could_not_resolve_itself_reach_the_gateway_and_are_refused(lane):
    cfg = build_launch_config("127.0.0.1", lane.gateway.port)
    session = raw_session(lane, cfg.chromium_args, ProxySettings(**cfg.profile_fields()["proxy"]))
    try:
        for url in (f"http://127.0.0.1:{lane.port + 1}/", "http://unlisted.test/"):
            with pytest.raises(DriverFault):
                session.goto(url, 8000)
        lane.gateway.wait_idle()
        reasons = [e["decision"]["reasons"] for e in lane.gateway.events()]
        assert ["DENY_NOT_LISTED"] in reasons
        assert "unlisted.test" in hosts(lane.gateway.events())                  # the name went to the gateway, not to a resolver
    finally:
        session.close()


def test_control_a_browser_with_no_proxy_reaches_loopback_and_the_gateway_sees_nothing(lane):
    off = policy_off_config()
    session = raw_session(lane, off.chromium_args, None)
    try:
        session.goto(f"http://127.0.0.1:{lane.port}/home", 8000)
        lane.gateway.wait_idle()
        assert len(lane.fixture.seen) >= 1 and lane.gateway.events() == []
    finally:
        session.close()


def test_control_a_proxy_without_the_loopback_override_is_bypassed_for_loopback(lane):
    """Documents Chromium's implicit bypass: with ``--proxy-server`` alone, loopback does not go to the proxy."""
    session = raw_session(lane, (f"--proxy-server=http://127.0.0.1:{lane.gateway.port}",), None)
    try:
        session.goto(f"http://127.0.0.1:{lane.port}/home", 8000)
        lane.gateway.wait_idle()
        assert len(lane.fixture.seen) >= 1, "the fixture was not reached"
        assert lane.gateway.events() == [], "the gateway saw loopback traffic without the override: re-examine qa_egress.launch"
    finally:
        session.close()
