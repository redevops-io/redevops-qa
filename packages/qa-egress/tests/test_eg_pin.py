# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Resolve then pin: the connection goes to the address the decision pinned, once resolved, and is checked afterwards.
Also what the gateway refuses on its own whatever a decider says. Only loopback sockets are opened (the connector is a seam
that maps a fake private address to a loopback port)."""
import asyncio
import threading
import time

import pytest
from agent_harness.qa.egress import AllowEntry, EgressDecision, EgressPolicy, EgressVerdict, parse_target
from qa_egress import Decider, EgressGateway, GatewayLimits

from qa_eg_support import (ScriptedResolver, SpyOpener, Upstream, get, make_gateway, ok, private_entry, raw_request)

NETS = ("10.0.0.0/24",)


def policy_for(port, *names, nets=NETS):
    return EgressPolicy(entries=tuple(AllowEntry(host=n, networks=nets, schemes=("http", "ws"), ports=(port,), private_ok=True) for n in names))


def test_the_connection_goes_to_the_first_answer_and_the_name_is_resolved_once():
    with Upstream() as victim, Upstream() as attacker:
        victim.default = ok("victim")
        attacker.default = ok("attacker")
        resolver = ScriptedResolver({"pin.test": [["10.0.0.5"], ["10.0.0.6"]]})
        spy = SpyOpener({"10.0.0.5": victim.port, "10.0.0.6": attacker.port})
        server, _ = make_gateway(victim.port, resolver, policy=policy_for(victim.port, "pin.test"), opener=spy)
        with server as gw:
            r = get(gw.port, f"http://pin.test:{victim.port}/x")
            assert r.status == 200 and r.body == b"victim"
            assert spy.calls == [("10.0.0.5", victim.port)] and resolver.calls == ["pin.test"]
            assert attacker.seen == []
            r2 = get(gw.port, f"http://pin.test:{victim.port}/y")                 # a new request is a new decision: the new answer
            assert r2.status == 200 and r2.body == b"attacker" and spy.calls[-1][0] == "10.0.0.6"


def test_a_connection_that_did_not_reach_the_pinned_address_is_refused_and_nothing_is_sent():
    with Upstream() as victim:
        spy = SpyOpener({"10.0.0.5": victim.port}, claim="10.0.0.99")
        resolver = ScriptedResolver({"pin.test": [["10.0.0.5"]]})
        server, _ = make_gateway(victim.port, resolver, policy=policy_for(victim.port, "pin.test"), opener=spy)
        with server as gw:
            r = get(gw.port, f"http://pin.test:{victim.port}/x")
            assert r.denied and r.reason == "DENY_PEER_MISMATCH"
            gw.wait_idle()
            assert victim.seen == []
            (rec,) = gw.records()
            assert "DENY_PEER_MISMATCH" in rec.decision.reasons and rec.outcome == "denied"


def test_the_connector_is_only_ever_given_an_address_literal_never_a_name():
    with Upstream() as victim:
        spy = SpyOpener({"10.0.0.5": victim.port, "10.0.0.7": victim.port})
        resolver = ScriptedResolver({"a.test": [["10.0.0.5"]], "b.test": [["10.0.0.7", "10.0.0.5"]]})
        server, _ = make_gateway(victim.port, resolver, policy=policy_for(victim.port, "a.test", "b.test"), opener=spy)
        with server as gw:
            for name in ("a.test", "b.test"):
                assert get(gw.port, f"http://{name}:{victim.port}/").status == 200
            import ipaddress
            assert [ipaddress.ip_address(a) for a, _ in spy.calls]
            assert [a for a, _ in spy.calls] == ["10.0.0.5", "10.0.0.5"]            # the first of the sorted answers


def test_a_connect_failure_and_a_connect_timeout_are_bad_gateway_and_gateway_timeout():
    with Upstream() as victim:
        resolver = ScriptedResolver({"a.test": [["10.0.0.5"]]})
        server, _ = make_gateway(victim.port, resolver, policy=policy_for(victim.port, "a.test"), opener=SpyOpener({}))
        with server as gw:
            r = get(gw.port, f"http://a.test:{victim.port}/")
            assert (r.status, r.reason) == (502, "CONNECT_FAILED")
            gw.wait_idle()
            assert gw.records()[0].outcome == "upstream_error"
        server2, _ = make_gateway(victim.port, resolver, policy=policy_for(victim.port, "a.test"),
                                  opener=SpyOpener({"10.0.0.5": victim.port}, delay=1.0), limits=GatewayLimits(connect_timeout_s=0.2))
        with server2 as gw2:
            r = get(gw2.port, f"http://a.test:{victim.port}/")
            assert (r.status, r.reason) == (504, "CONNECT_TIMEOUT")


def test_a_name_that_does_not_resolve_in_time_is_refused_quickly():
    class Slow:
        def resolve(self, host):
            time.sleep(1.5)
            return ["10.0.0.5"]
    with Upstream() as victim:
        server, _ = make_gateway(victim.port, Slow(), policy=policy_for(victim.port, "slow.test"), opener=SpyOpener({"10.0.0.5": victim.port}),
                                 limits=GatewayLimits(dns_timeout_s=0.2))
        with server as gw:
            started = time.monotonic()
            r = get(gw.port, f"http://slow.test:{victim.port}/")
            assert r.denied and r.reason == "DENY_RESOLVER_ERROR" and time.monotonic() - started < 1.2
            assert victim.seen == []


def test_two_requests_resolve_concurrently_and_share_no_decision_state():
    gate = threading.Barrier(2, timeout=3)

    class Rendezvous:
        def __init__(self):
            self.calls = []

        def resolve(self, host):
            self.calls.append(host)
            gate.wait()                                   # both lookups must be in flight together
            return ["10.0.0.5"] if host == "a.test" else ["10.0.0.9"]
    with Upstream() as victim:
        spy = SpyOpener({"10.0.0.5": victim.port, "10.0.0.9": victim.port})
        server, _ = make_gateway(victim.port, Rendezvous(), policy=policy_for(victim.port, "a.test", "b.test"), opener=spy)
        with server as gw:
            out = {}
            threads = [threading.Thread(target=lambda n=n: out.__setitem__(n, get(gw.port, f"http://{n}:{victim.port}/"))) for n in ("a.test", "b.test")]
            [t.start() for t in threads]
            [t.join(5) for t in threads]
            assert out["a.test"].status == 200 and out["b.test"].status == 200
            assert sorted(a for a, _ in spy.calls) == ["10.0.0.5", "10.0.0.9"]


# ---- what the gateway refuses whatever the decider says ----------------------------------------------------------------------------
class AllowEverything(Decider):
    """A deliberately wrong decider: it allows any URL and pins the address it is told to (default: the URL's own literal)."""

    policy_id = "rcv1:" + "0" * 64

    def __init__(self, pinned=None, addresses=None):
        self.pinned, self.addresses = pinned, addresses

    def _allow(self, url, purpose):
        t = parse_target(url)
        literal = t.host if t.kind != "NAME" else "10.0.0.5"
        pinned = self.pinned if self.pinned is not None else literal
        return EgressDecision(verdict=EgressVerdict.ALLOW, reasons=("ALLOWED_PRIVATE_OPERATOR",), purpose=purpose, hop=0,
                              policy_id=self.policy_id, scheme=t.scheme, host=t.host, port=t.port, host_kind=t.kind,
                              addresses=tuple(self.addresses) if self.addresses is not None else (literal,),
                              pinned_address=pinned, mode="PRIVATE_OPERATOR", entry="wrong", resolved=True)

    async def decide_url(self, url, *, purpose, hop, previous_scheme):
        return self._allow(url, purpose)

    async def decide_connect(self, host, port):
        return self._allow(f"https://{host if ':' not in host else '[' + host + ']'}:{port}/", "connection")

    async def decide_redirect(self, previous_url, location, *, hop, previous):
        return self._allow(location, "redirect")


@pytest.mark.parametrize("url,pinned,addresses,reason", [
    ("http://169.254.169.254/", None, None, "DENY_METADATA_ADDRESS"),
    ("http://[fd00:ec2::254]/", None, None, "DENY_METADATA_ADDRESS"),
    ("http://100.100.100.200/", None, None, "DENY_METADATA_ADDRESS"),
    ("http://app.test/", "169.254.169.254", ("10.0.0.5",), "DENY_METADATA_ADDRESS"),          # a pin the addresses do not show
    ("http://app.test/", "fe80::1", ("10.0.0.5",), "DENY_METADATA_ADDRESS"),
    ("http://app.test/", "0.0.0.0", ("10.0.0.5",), "DENY_ADDRESS_NOT_PUBLIC"),
    ("http://app.test/", "224.0.0.1", ("10.0.0.5",), "DENY_ADDRESS_NOT_PUBLIC"),
    ("http://app.test/", "::ffff:127.0.0.1", ("10.0.0.5",), "DENY_ADDRESS_NOT_PUBLIC"),
    ("http://app.test/", "64:ff9b::7f00:1", ("10.0.0.5",), "DENY_ADDRESS_NOT_PUBLIC"),
    ("http://app.test/", "not-an-address", ("10.0.0.5",), "DENY_RESOLVER_BAD_ANSWER"),
    ("http://app.test/", "app.test", ("10.0.0.5",), "DENY_RESOLVER_BAD_ANSWER"),
    ("http://app.test/", "", ("10.0.0.5",), "DENY_RESOLVER_BAD_ANSWER"),
    ("http://app.test/", "::", ("10.0.0.5",), "DENY_ADDRESS_NOT_PUBLIC"),
])
def test_the_gateway_refuses_to_connect_to_what_can_never_be_admitted_even_if_the_decider_allows_it(url, pinned, addresses, reason):
    spy = SpyOpener({})
    server, _ = make_gateway(1, ScriptedResolver(), policy=EgressPolicy(entries=()), opener=spy,
                             decider=AllowEverything(pinned=pinned, addresses=addresses))
    with server as gw:
        r = get(gw.port, url)
        assert r.denied and r.reason == reason
        assert spy.calls == []


def test_the_same_holds_for_connect_and_for_a_redirect_target():
    spy = SpyOpener({})
    with Upstream() as up:
        up.default = ok("x")
        from qa_eg_support import redirect
        up.routes["/r"] = redirect("http://169.254.169.254/")
        spy.table["10.0.0.5"] = up.port
        server, _ = make_gateway(1, ScriptedResolver(), policy=EgressPolicy(entries=()), opener=spy, decider=AllowEverything())
        with server as gw:
            r = raw_request(gw.port, b"CONNECT 169.254.169.254:443 HTTP/1.1\r\n\r\n")
            assert r.denied and r.reason == "DENY_METADATA_ADDRESS"
            r2 = get(gw.port, f"http://app.test:{up.port}/r")                      # the origin is "allowed"; its redirect is not
            assert r2.denied and r2.reason == "DENY_METADATA_ADDRESS" and "location" not in r2.headers
            assert spy.calls == [("10.0.0.5", up.port)]


def test_a_decision_with_no_pinned_address_is_refused():
    class NoPin(AllowEverything):
        def _allow(self, url, purpose):
            d = super()._allow(url, purpose)
            return EgressDecision(verdict=d.verdict, reasons=d.reasons, purpose=d.purpose, hop=0, policy_id=d.policy_id, scheme=d.scheme,
                                  host=d.host, port=d.port, host_kind=d.host_kind, addresses=d.addresses, pinned_address=None,
                                  mode=d.mode, resolved=True)
    spy = SpyOpener({})
    server, _ = make_gateway(1, ScriptedResolver(), policy=EgressPolicy(entries=()), opener=spy, decider=NoPin())
    with server as gw:
        r = get(gw.port, "http://app.test/")
        assert r.denied and r.reason == "DENY_NO_ADDRESSES" and spy.calls == []


def test_the_system_resolver_returns_each_address_once_in_a_stable_order(monkeypatch):
    import socket
    from qa_egress import SystemResolver
    answer = [(socket.AF_INET6, 0, 0, "", ("2001:db8::1", 0, 0, 0)), (socket.AF_INET, 0, 0, "", ("93.184.216.34", 0)),
              (socket.AF_INET, 0, 0, "", ("93.184.216.34", 0)), (socket.AF_UNIX, 0, 0, "", "/tmp/x")]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answer)
    assert SystemResolver().resolve("x.test") == ["2001:db8::1", "93.184.216.34"]
