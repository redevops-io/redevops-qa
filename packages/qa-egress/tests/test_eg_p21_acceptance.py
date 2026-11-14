# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""P2-1 gateway criteria (AC-6 to AC-8) for an external origin, against the real gateway on loopback. The policy is the one the runner derives for the plan's origin
(``qa_runner.egress.policy_config``): the origin IS the egress scope, one literal loopback address and one port, and nothing is added to the gateway for it."""
from agent_harness.qa.egress import EgressPolicy

from qa_runner.egress import policy_config

from qa_eg_support import Upstream, get, make_gateway, redirect


def external_gateway(up):
    origin = f"http://127.0.0.1:{up.port}"
    policy = EgressPolicy.from_config(policy_config("origin-only", origin))
    server, resolver = make_gateway(up.port, policy=policy)
    return origin, server, resolver


def test_ac6_the_origin_is_relayed_and_an_address_outside_the_declared_range_is_refused_with_its_reason_and_never_contacted():
    with Upstream() as up:
        origin, server, resolver = external_gateway(up)
        with server as gw:
            assert get(gw.port, origin + "/health").status == 200
            gw.wait_idle()
            seen = len(up.seen)
            for other in ("http://93.184.216.34:%d/" % up.port, "http://10.0.0.5:%d/" % up.port, "http://127.0.0.2:%d/" % up.port, "http://127.0.0.1:%d/" % (up.port + 1)):
                r = get(gw.port, other)
                assert r.denied and r.reason in ("DENY_NOT_LISTED", "DENY_PORT_NOT_LISTED"), (other, r.reason)
            gw.wait_idle()
            assert len(up.seen) == seen, "a refused request reached the origin"
            recs = gw.records()
            assert [r.outcome for r in recs].count("relayed") == 1 and all(not r.decision.allowed for r in recs[1:])
            assert resolver.calls == [], "no name was looked up: the policy lists no name"


def test_ac7_a_redirect_from_the_origin_to_a_host_outside_the_policy_is_refused_per_hop_and_recorded():
    with Upstream() as up:
        up.routes["/go"] = redirect("http://127.0.0.1:%d/elsewhere" % (up.port + 1))
        up.routes["/go2"] = redirect("http://93.184.216.34/")
        origin, server, _ = external_gateway(up)
        with server as gw:
            for path in ("/go", "/go2"):
                r = get(gw.port, origin + path)
                assert r.denied and "location" not in r.headers
            gw.wait_idle()
            recs = gw.records()
            assert len(recs) == 2 and all(rec.redirect_decision is not None and not rec.redirect_decision.allowed for rec in recs)
            assert [e.path for e in up.seen] == ["/go", "/go2"] if hasattr(up.seen[0], "path") else len(up.seen) == 2


def test_ac8_a_name_that_resolves_to_the_origin_is_not_the_origin_and_a_changing_answer_is_never_connected_to():
    with Upstream() as up:
        origin, server, resolver = external_gateway(up)
        resolver.set("app.test", ["127.0.0.1"], ["169.254.169.254"])                 # the first answer is loopback, the next one is not
        with server as gw:
            for _ in range(2):
                r = get(gw.port, f"http://app.test:{up.port}/")
                assert r.denied and r.reason == "DENY_NOT_LISTED"
            gw.wait_idle()
            assert up.seen == [] and resolver.calls == [], "the name was resolved or contacted although the policy does not list it"
            assert get(gw.port, origin + "/health").status == 200, "the literal origin still works: the pin is the literal address"
