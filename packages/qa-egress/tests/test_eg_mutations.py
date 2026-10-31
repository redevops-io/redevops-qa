# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Mutation tests for the enforcement point: each guard is checked by a property run against the REAL gateway over loopback;
the real gateway passes it, and a gateway with that one guard removed fails it. The properties use only loopback sockets (the
connector seam maps fake addresses to loopback ports and refuses any address it has no mapping for)."""
import asyncio
import socket
import time

import pytest
from agent_harness.qa.egress import EgressPolicy, Refused
from qa_egress import EgressGateway, GatewayLimits
from qa_egress.gateway import Refusal

from test_eg_pin import AllowEverything, policy_for
from qa_eg_support import (RawUpstream, ScriptedResolver, SpyOpener, Upstream, get, make_gateway, ok, private_entry, raw_request,
                           redirect, stream)


# -- the properties --------------------------------------------------------------------------------------------------------------

def prop_metadata_is_refused_even_if_the_decision_allows_it(cls):
    spy = SpyOpener({})
    server, _ = make_gateway(1, ScriptedResolver(), policy=EgressPolicy(entries=()), opener=spy, decider=AllowEverything(), gateway_class=cls)
    with server as gw:
        r = get(gw.port, "http://169.254.169.254/latest/meta-data/")
        assert r.denied, "a metadata address was not refused"
        assert spy.calls == [], "the gateway tried to connect to a metadata address"
        r2 = raw_request(gw.port, b"CONNECT 169.254.169.254:443 HTTP/1.1\r\n\r\n")
        assert r2.denied and spy.calls == []


def prop_the_connection_goes_to_the_pinned_address(cls):
    with Upstream() as victim, Upstream() as attacker:
        victim.default, attacker.default = ok("victim"), ok("attacker")
        resolver = ScriptedResolver({"pin.test": [["10.0.0.5"], ["10.0.0.6"]]})
        spy = SpyOpener({"10.0.0.5": victim.port, "10.0.0.6": attacker.port})
        server, _ = make_gateway(victim.port, resolver, policy=policy_for(victim.port, "pin.test"), opener=spy, gateway_class=cls)
        with server as gw:
            r = get(gw.port, f"http://pin.test:{victim.port}/x")
            assert r.body == b"victim", "the request went to a different address than the one the decision pinned"
            assert attacker.seen == [] and [a for a, _ in spy.calls] == ["10.0.0.5"]


def prop_a_redirect_to_metadata_is_never_relayed(cls):
    with Upstream() as up:
        up.routes["/go"] = redirect("http://169.254.169.254/latest/meta-data/")
        server, _ = make_gateway(up.port, gateway_class=cls)
        with server as gw:
            r = get(gw.port, f"http://app.test:{up.port}/go")
            assert r.denied and "location" not in r.headers, "a redirect to a metadata address reached the client"


def prop_a_redirect_chain_is_cut(cls):
    with Upstream() as up:
        for i in range(12):
            up.routes[f"/c{i}"] = redirect(f"http://app.test:{up.port}/c{i + 1}")
        server, _ = make_gateway(up.port, gateway_class=cls)
        with server as gw:
            url, hops = f"http://app.test:{up.port}/c0", 0
            while True:
                r = get(gw.port, url)
                if r.status != 302:
                    break
                hops += 1
                url = r.headers["location"]
                assert hops < 12, "an endless redirect chain was relayed"
            assert r.denied and hops == 5


def prop_an_oversized_response_is_bounded(cls):
    with Upstream() as up:
        up.routes["/big"] = stream(2 * 1024 * 1024, False)
        up.routes["/declared"] = stream(2 * 1024 * 1024, True)
        server, _ = make_gateway(up.port, limits=GatewayLimits(max_response_bytes=64 * 1024, read_timeout_s=2.0, idle_timeout_s=2.0,
                                                               total_timeout_s=6.0), gateway_class=cls)
        with server as gw:
            r = get(gw.port, f"http://app.test:{up.port}/big")
            assert len(r.body) <= 64 * 1024, "a response beyond the bound was relayed"
            r2 = get(gw.port, f"http://app.test:{up.port}/declared")
            assert r2.status == 502 and len(r2.raw) < 4096, "a declared oversized response was relayed"


def prop_a_tunnel_is_bounded(cls):
    with RawUpstream("echo") as raw:
        server, _ = make_gateway(raw.port, policy=EgressPolicy(entries=(private_entry("app.test", raw.port, schemes=("https",)),)),
                                 limits=GatewayLimits(max_tunnel_bytes=8 * 1024, idle_timeout_s=2.0, tunnel_total_timeout_s=5.0),
                                 gateway_class=cls)
        with server as gw:
            with socket.create_connection(("127.0.0.1", gw.port), timeout=3) as s:
                s.settimeout(3)
                s.sendall(f"CONNECT app.test:{raw.port} HTTP/1.1\r\n\r\n".encode())
                s.recv(4096)
                got = 0
                try:
                    for _ in range(64):
                        s.sendall(b"z" * 1024)
                        chunk = s.recv(65536)
                        if not chunk:
                            break
                        got += len(chunk)
                except OSError:
                    pass
            assert got <= 8 * 1024, "a tunnel carried more than its bound"


def prop_a_request_body_is_bounded(cls):
    with Upstream() as up:
        server, _ = make_gateway(up.port, limits=GatewayLimits(max_request_body_bytes=1024, read_timeout_s=2.0), gateway_class=cls)
        with server as gw:
            r = get(gw.port, f"http://app.test:{up.port}/p", method="POST", body=b"x" * 8192)
            assert r.status == 413 and up.seen == [], "an oversized request body was forwarded"


def prop_connections_are_bounded(cls):
    with Upstream() as up:
        server, _ = make_gateway(up.port, limits=GatewayLimits(max_connections=2, read_timeout_s=2.0), gateway_class=cls)
        with server as gw:
            held = [socket.create_connection(("127.0.0.1", gw.port), timeout=3) for _ in range(2)]
            time.sleep(0.2)
            try:
                r = raw_request(gw.port, b"GET http://app.test:1/ HTTP/1.1\r\n\r\n")
                assert r.status == 503, "a connection beyond the bound was served"
            finally:
                for s in held:
                    s.close()


def prop_unlisted_names_are_refused_and_not_resolved(cls):
    with Upstream() as up:
        resolver = ScriptedResolver({"app.test": [["127.0.0.1"]], "evil.test": [["127.0.0.1"]]})
        server, _ = make_gateway(up.port, resolver, gateway_class=cls)
        with server as gw:
            r = get(gw.port, f"http://evil.test:{up.port}/")
            assert r.denied and resolver.calls == [] and up.seen == []


def prop_the_peer_is_verified(cls):
    with Upstream() as victim:
        spy = SpyOpener({"10.0.0.5": victim.port}, claim="10.0.0.99")
        server, _ = make_gateway(victim.port, ScriptedResolver({"pin.test": [["10.0.0.5"]]}), policy=policy_for(victim.port, "pin.test"),
                                 opener=spy, gateway_class=cls)
        with server as gw:
            r = get(gw.port, f"http://pin.test:{victim.port}/")
            assert r.denied and victim.seen == [], "a connection that did not reach the pinned address was used"


def prop_origin_form_requests_are_refused(cls):
    with Upstream() as up:
        server, _ = make_gateway(up.port, gateway_class=cls)
        with server as gw:
            r = raw_request(gw.port, b"GET /x HTTP/1.1\r\nHost: app.test\r\n\r\n")
            assert r.status == 400 and up.seen == []


def prop_a_smuggling_shaped_request_is_refused(cls):
    with Upstream() as up:
        server, _ = make_gateway(up.port, gateway_class=cls)
        with server as gw:
            r = raw_request(gw.port, f"POST http://app.test:{up.port}/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".encode())
            assert r.status == 501 and up.seen == []


def prop_https_is_not_relayed_in_the_clear(cls):
    with Upstream() as up:
        server, _ = make_gateway(up.port, policy=EgressPolicy(entries=(private_entry("app.test", up.port, schemes=("https",)),)),
                                 gateway_class=cls)
        with server as gw:
            r = get(gw.port, f"https://app.test:{up.port}/")
            assert r.status == 400 and up.seen == []


# -- the mutants: one guard each ----------------------------------------------------------------------------------------------------

class NoMetadataRefusal(EgressGateway):
    """The enforcement path without its own metadata refusal (the policy's is not what is tested here)."""

    def _enforce(self, decision):
        return decision

    @staticmethod
    def _assert_connectable(address):
        return None


class NoPinConnect(EgressGateway):
    """Connects by resolving the name again (the DNS-rebinding hole), not to the pinned address."""

    async def _connect(self, decision):
        answers = self._decider._resolver.resolve(decision.host)
        reader, writer, _peer = await asyncio.wait_for(self._opener(answers[0], decision.port), self.limits.connect_timeout_s)
        self._track(writer)
        return reader, writer


class NoRedirectRecheck(EgressGateway):
    async def _check_redirect(self, code, headers, judged, decision, hop, writer, st):
        return None


class EndlessRedirects(EgressGateway):
    async def _check_redirect(self, code, headers, judged, decision, hop, writer, st):
        return None


class NoResponseCap(EgressGateway):
    def _response_over_cap(self, size):
        return False


class NoTunnelCap(EgressGateway):
    def _tunnel_over_cap(self, size):
        return False


class NoRequestBodyCap(EgressGateway):
    def _request_body_over_cap(self, size):
        return False


class NoConnectionCap(EgressGateway):
    def _at_capacity(self):
        return False


class DecidesNothing(EgressGateway):
    """Every decision is an allow of the literal request, without the policy (default deny gone)."""

    def __init__(self, policy, resolver, **kwargs):
        kwargs["decider"] = AllowEverything()
        super().__init__(policy, resolver, **kwargs)


class NoPeerCheck(EgressGateway):
    async def _connect(self, decision):
        address, port, _ = decision.connect_target()
        self._assert_connectable(address)
        reader, writer, _peer = await asyncio.wait_for(self._opener(address, port), self.limits.connect_timeout_s)
        self._track(writer)
        return reader, writer


class AcceptsOriginForm(EgressGateway):
    async def _http_flow(self, req, reader, writer, st, budget):
        if req.target.startswith("/"):
            from qa_egress.gateway import _Request
            req = _Request(req.method, f"http://app.test{req.target}", req.version, req.headers, req.prefix)
        return await super()._http_flow(req, reader, writer, st, budget)


class IgnoresTransferCoding(EgressGateway):
    async def _http_flow(self, req, reader, writer, st, budget):
        req.headers[:] = [h for h in req.headers if h[0] != "transfer-encoding"]
        return await super()._http_flow(req, reader, writer, st, budget)


class RelaysHttpsInTheClear(EgressGateway):
    async def _http_flow(self, req, reader, writer, st, budget):
        if req.target.startswith("https://"):
            req = type(req)(req.method, "http://" + req.target[8:], req.version, req.headers, req.prefix)
        return await super()._http_flow(req, reader, writer, st, budget)


class ResolvesBeforeListing(EgressGateway):
    """Looks every name up, listed or not (a DNS query leaves for a host the operator never listed)."""

    def __init__(self, policy, resolver, **kwargs):
        self._probe = resolver
        super().__init__(policy, resolver, **kwargs)

    async def _http_flow(self, req, reader, writer, st, budget):
        try:
            host = req.target.split("//", 1)[1].split("/", 1)[0].split(":")[0]
            self._probe.resolve(host)
        except Exception:
            pass
        return await super()._http_flow(req, reader, writer, st, budget)


MUTATIONS = [
    ("metadata refusal removed from the enforcement path", prop_metadata_is_refused_even_if_the_decision_allows_it, NoMetadataRefusal),
    ("connect by name instead of the pinned address", prop_the_connection_goes_to_the_pinned_address, NoPinConnect),
    ("redirect re-check removed", prop_a_redirect_to_metadata_is_never_relayed, NoRedirectRecheck),
    ("redirect chain not counted", prop_a_redirect_chain_is_cut, EndlessRedirects),
    ("response size cap removed", prop_an_oversized_response_is_bounded, NoResponseCap),
    ("tunnel byte cap removed", prop_a_tunnel_is_bounded, NoTunnelCap),
    ("request body cap removed", prop_a_request_body_is_bounded, NoRequestBodyCap),
    ("connection cap removed", prop_connections_are_bounded, NoConnectionCap),
    ("the policy is not consulted", prop_unlisted_names_are_refused_and_not_resolved, DecidesNothing),
    ("peer verification removed", prop_the_peer_is_verified, NoPeerCheck),
    ("origin-form requests accepted", prop_origin_form_requests_are_refused, AcceptsOriginForm),
    ("transfer coding ignored", prop_a_smuggling_shaped_request_is_refused, IgnoresTransferCoding),
    ("https relayed in the clear", prop_https_is_not_relayed_in_the_clear, RelaysHttpsInTheClear),
    ("an unlisted name is looked up", prop_unlisted_names_are_refused_and_not_resolved, ResolvesBeforeListing),
]


@pytest.mark.parametrize("label,prop,mutant", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_removing_one_guard_makes_the_suite_fail(label, prop, mutant):
    prop(EgressGateway)                                # the real gateway satisfies the property
    with pytest.raises(AssertionError):
        prop(mutant)                                   # the same property fails, by its own assertion, without the guard


def test_the_mutated_gateways_are_distinct_subclasses_of_the_real_one():
    assert all(issubclass(m[2], EgressGateway) and m[2] is not EgressGateway for m in MUTATIONS)
    assert len({m[0] for m in MUTATIONS}) == len(MUTATIONS)
