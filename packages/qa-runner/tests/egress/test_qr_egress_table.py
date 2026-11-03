# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The hostile-page egress table (QA_PROD_00 section 5.3), reproduced against the real Chromium, the egress gateway and the launch configuration the browser lane uses.

One page on the allowed origin tries to reach a hostile TCP origin and a UDP listener (both on loopback, neither is on the allow-list) in every way a page can. Three configurations:

* PROTECTED: the launch configuration of ``qa_egress`` and a gateway whose policy is the lane's own origin-only profile for the allowed origin. The hostile origin must see nothing.
* CONTROL, no proxy: Chromium's defaults. It must reach the hostile origin by every path.
* CONTROL, ``--proxy-server`` only (what a driver does that adds a proxy flag and nothing else): Chromium sends loopback around the proxy. It must reach the hostile origin by every path.

The controls are what make the protected result worth anything: a path the controls do not reach says nothing about the protections, so each path is tested against both controls. A control that
stops bypassing means the pinned Chromium or Playwright changed and the launch configuration must be re-examined; that failure is what this lane is for.

What this shows: for the pinned Playwright 1.64.1 and its Chromium, on the host that runs it (CI: ubuntu-24.04, Linux x86_64), headless, over HTTP, the listed requests of a page do not reach a
loopback origin the policy does not list. It does not show anything about HTTPS interception, DNS rebinding at browser level, headed mode, other browsers or other engines."""
import ipaddress
import time

import pytest

from qa_egress import GatewayServer, build_launch_config, policy_off_config
from qa_egress.resolver import SystemResolver
from qa_playwright import ContextSpec, PlaywrightDriver, ProxySettings
from qa_runner.egress import policy_config
from hostile_world import HTTPS_PAGE, PATHS, WSS_PAGE, HostileWorld

SETTLE_MS = 4000          # a protected browser has nothing to wait for: it is given this long to do something it should not
CONTROL_WAIT_S = 30.0     # a control is waited for until it has reached every path (and sent a datagram), so a slow host cannot make a path look unreachable


def run_config(world, gateway, name, launch_args, proxy, *, until=None):
    """One browser session loading the hostile page; returns what the hostile listeners and the gateway saw. ``until`` (controls only): waited for, up to CONTROL_WAIT_S, until it is true of what
    the hostile listeners have seen, so a slow host cannot make something look unreachable."""
    world.reset()
    gateway.drain_records()
    driver = PlaywrightDriver()
    session = driver.new_session(ContextSpec(session_id=f"egress-{name}", profile_id="lane", launch_args=tuple(launch_args), proxy=proxy, request_gate=None))
    try:
        session.goto(world.origin + "/page", 15000)
        session.settle(SETTLE_MS)
        if until is not None:
            end = time.monotonic() + CONTROL_WAIT_S
            while time.monotonic() < end and not until(world.snapshot()):
                session.settle(500)
        gateway.wait_idle(15)
    finally:
        session.close()
        driver.close()
    seen = world.snapshot()
    seen["gateway"] = gateway.events()
    return seen


def run_three(up, page, *, until):
    """The protected configuration and the two controls, one after the other, against one world that serves ``page``."""
    results = {}
    with HostileWorld(page) as world:
        policy = up.harness.egress.EgressPolicy.from_config(policy_config("origin-only", world.origin))
        with GatewayServer(policy, SystemResolver()) as gateway:
            fields = build_launch_config("127.0.0.1", gateway.port).profile_fields()
            results["protected"] = run_config(world, gateway, "protected", fields["launch_args"], ProxySettings(**fields["proxy"]))
            results["control-noproxy"] = run_config(world, gateway, "control-noproxy", policy_off_config().chromium_args, None, until=until)
            results["control-proxy-only"] = run_config(world, gateway, "control-proxy-only", (f"--proxy-server=http://127.0.0.1:{gateway.port}",), None, until=until)
        results["ports"] = {"a": world.a_port, "b": world.b_port}
    return results


@pytest.fixture(scope="module")
def table(up):
    """Each configuration once, in order, against one world; the policy lists the allowed origin and nothing else."""
    from hostile_world import PAGE
    return run_three(up, PAGE, until=lambda now: set(PATHS) <= now["b_hits"] and now["udp"] > 0 and now["b_connections"] > 0)


#: pages that make only a TCP connection to the hostile origin (no HTTP request line it could count): the row is the page, the evidence is the number of connections the origin accepted
CONNECTION_ROWS = {"https-image": HTTPS_PAGE, "wss-websocket": WSS_PAGE}


@pytest.fixture(scope="module", params=sorted(CONNECTION_ROWS))
def connection_row(request, up):
    return request.param, run_three(up, CONNECTION_ROWS[request.param], until=lambda now: now["b_connections"] > 0)


def is_loopback_name(host):
    """``localhost``, or a loopback address in any spelling the gateway logs (it writes an IPv6 literal in full: 0000:...:0001)."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def decisions(result):
    return [e["decision"] for e in result["gateway"] if e.get("decision")]


@pytest.mark.parametrize("path", PATHS)
def test_the_hostile_origin_is_reached_by_the_path_only_when_the_protections_are_off(table, path):
    assert path in table["control-noproxy"]["b_hits"], f"control (no proxy) did not reach the hostile origin by {path}: the path proves nothing; saw {sorted(table['control-noproxy']['b_hits'])}"
    assert path in table["control-proxy-only"]["b_hits"], f"control (--proxy-server only) did not reach the hostile origin by {path}: saw {sorted(table['control-proxy-only']['b_hits'])}"
    assert path not in table["protected"]["b_hits"], f"the PROTECTED browser reached the hostile origin by {path}"


def test_the_protected_browser_sent_the_hostile_origin_nothing_at_all(table):
    assert table["protected"]["b_hits"] == frozenset(), sorted(table["protected"]["b_hits"])


def test_the_protected_browser_opened_no_connection_at_all_to_the_hostile_origin_and_the_controls_did(table):
    """Connections, not request lines: a bare TCP connect, a preconnect and a TLS ClientHello are not HTTP requests and would not show in the paths above."""
    assert table["control-noproxy"]["b_connections"] > 0 and table["control-proxy-only"]["b_connections"] > 0
    assert table["protected"]["b_connections"] == 0, table["protected"]["b_connections"]


def test_a_page_that_can_only_open_a_tls_connection_reaches_the_hostile_origin_only_when_the_protections_are_off(connection_row):
    row, result = connection_row
    assert result["control-noproxy"]["b_connections"] > 0, f"control (no proxy) opened no connection for the {row} page: the row proves nothing"
    assert result["control-proxy-only"]["b_connections"] > 0, f"control (--proxy-server only) opened no connection for the {row} page: the row proves nothing"
    assert result["protected"]["b_connections"] == 0, f"the PROTECTED browser opened {result['protected']['b_connections']} connection(s) to the hostile origin ({row})"
    assert result["protected"]["b_hits"] == frozenset()
    assert {d["verdict"] for d in decisions(result["protected"]) if d["port"] == result["ports"]["b"]} <= {"DENY"}


def test_a_bare_tcp_connection_to_the_hostile_origin_is_counted_though_no_request_line_follows():
    """The counter itself: a connect that sends nothing (or a TLS ClientHello) leaves no request path, and must still be a connection."""
    import socket
    with HostileWorld() as world:
        socket.create_connection(("127.0.0.1", world.b_port), timeout=5).close()
        socket.create_connection(("127.0.0.1", world.b_port), timeout=5).close()
        end = time.monotonic() + 5
        while time.monotonic() < end and world.snapshot()["b_connections"] < 2:
            time.sleep(0.05)
        seen = world.snapshot()
    assert seen["b_connections"] == 2 and seen["b_hits"] == frozenset()


def test_the_protected_browser_sent_the_hostile_udp_listener_nothing_and_the_controls_did(table):
    assert table["control-noproxy"]["udp"] > 0 and table["control-proxy-only"]["udp"] > 0, (table["control-noproxy"]["udp"], table["control-proxy-only"]["udp"])
    assert table["protected"]["udp"] == 0


def test_the_protected_browser_did_load_the_allowed_page_so_the_silence_is_not_a_browser_that_did_nothing(table):
    protected = table["protected"]
    assert {"/page", "/redir", "/allowed-self"} <= protected["a_seen"], sorted(protected["a_seen"])
    assert any(d["verdict"] == "ALLOW" for d in decisions(protected))


def test_the_gateway_allowed_the_allowed_origin_and_refused_everything_else_with_the_reason_not_listed(table):
    protected, a, b = table["protected"], table["ports"]["a"], table["ports"]["b"]
    rows = decisions(protected)
    allowed = {(d["host"], d["port"]) for d in rows if d["verdict"] == "ALLOW"}
    assert allowed == {("127.0.0.1", a)}, sorted(allowed)
    for d in rows:
        if d["verdict"] != "ALLOW":
            assert d["verdict"] == "DENY" and d["reasons"] == ["DENY_NOT_LISTED"], d
    refused_b = {(d["host"], d["port"]) for d in rows if d["verdict"] == "DENY" and d["port"] == b}
    hosts = {h for h, _ in refused_b}
    assert "127.0.0.1" in hosts and "localhost" in hosts and "hostile.invalid" in hosts, sorted(hosts)
    assert any(":" in h and is_loopback_name(h) for h in hosts), f"the IPv6 literal was not refused by the gateway: {sorted(hosts)}"


def test_the_redirect_the_websocket_and_the_connect_to_the_hostile_origin_were_each_decided_and_refused(table):
    kinds = {e["request_kind"] for e in table["protected"]["gateway"] if e.get("decision") and e["decision"]["port"] == table["ports"]["b"] and e["decision"]["verdict"] == "DENY"}
    assert {"http", "connect", "redirect"} <= kinds, sorted(kinds)


def test_the_gateway_saw_nothing_when_the_browser_had_no_proxy(table):
    assert table["control-noproxy"]["gateway"] == []


def test_the_gateway_never_saw_loopback_when_the_proxy_flag_stood_alone(table):
    """The audit's central finding for a driver that only adds ``--proxy-server``: the browser sends loopback around the proxy, so the gateway cannot decide it."""
    b = table["ports"]["b"]
    seen = [(d["host"], d["port"]) for d in decisions(table["control-proxy-only"])]
    assert [(h, p) for h, p in seen if is_loopback_name(h)] == [], seen
    assert all(p == b for _, p in seen)                                  # what the gateway did see: only the name the browser could not resolve itself
