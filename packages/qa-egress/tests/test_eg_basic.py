# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The gateway end to end over loopback: a relayed request, a refused one, a tunnel, a redirect, an upgrade."""
import socket

from qa_egress import GatewayServer

from qa_eg_support import Upstream, get, make_gateway, ok, raw_request, redirect, websocket_echo


def test_a_listed_name_is_relayed_to_the_pinned_address_with_a_rewritten_request():
    with Upstream() as up:
        server, resolver = make_gateway(up.port)
        with server as gw:
            r = get(gw.port, f"http://app.test:{up.port}/hello?x=1", headers=[("Host", "evil.test"), ("Proxy-Authorization", "Basic zzz"),
                                                                         ("Connection", "keep-alive, X-Secret"), ("X-Secret", "1"), ("X-Ok", "yes")])
            assert r.status == 200 and r.body == b"hello"
            gw.wait_idle()
            (seen,) = up.seen
            assert seen.request_line == "GET /hello?x=1 HTTP/1.1"
            assert seen.headers["host"] == f"app.test:{up.port}" and seen.headers["x-ok"] == "yes"
            assert "proxy-authorization" not in seen.headers and "x-secret" not in seen.headers
            assert seen.headers["connection"] == "close"
            (rec,) = gw.records()
            assert rec.outcome == "relayed" and rec.decision.allowed and rec.decision.pinned_address == "127.0.0.1"
            assert resolver.calls == ["app.test"]


def test_an_unlisted_host_is_refused_and_no_upstream_connection_is_made():
    with Upstream() as up:
        server, resolver = make_gateway(up.port)
        with server as gw:
            r = get(gw.port, f"http://other.test:{up.port}/")
            assert r.denied and r.reason == "DENY_NOT_LISTED"
            gw.wait_idle()
            assert up.seen == [] and resolver.calls == []          # an unlisted name is not even looked up


def test_connect_to_a_listed_https_origin_is_tunnelled_and_connect_elsewhere_is_refused():
    with Upstream() as up:
        up.default = websocket_echo                                 # any byte echo will do for a tunnel
        from qa_eg_support import private_entry
        from agent_harness.qa.egress import EgressPolicy
        policy = EgressPolicy(entries=(private_entry("app.test", up.port, schemes=("https",)),))
        server, _ = make_gateway(up.port, policy=policy)
        with server as gw:
            with socket.create_connection(("127.0.0.1", gw.port), timeout=3) as s:
                s.settimeout(3)
                s.sendall(f"CONNECT app.test:{up.port} HTTP/1.1\r\nHost: app.test:{up.port}\r\n\r\n".encode())
                head = s.recv(4096)
                assert head.startswith(b"HTTP/1.1 200 Connection Established")
            r = raw_request(gw.port, b"CONNECT 169.254.169.254:443 HTTP/1.1\r\n\r\n")
            assert r.denied and r.reason == "DENY_METADATA_ADDRESS"


def test_a_redirect_to_the_metadata_address_is_refused_before_the_client_sees_it():
    with Upstream() as up:
        up.routes["/go"] = redirect("http://169.254.169.254/latest/meta-data/")
        server, _ = make_gateway(up.port)
        with server as gw:
            r = get(gw.port, f"http://app.test:{up.port}/go")
            assert r.status == 403 and r.denied and "location" not in r.headers and b"169" not in r.raw
            gw.wait_idle()
            rec = gw.records()[0]
            assert rec.redirect_decision is not None and "DENY_METADATA_ADDRESS" in rec.redirect_decision.reasons


def test_a_websocket_upgrade_is_relayed_in_both_directions():
    with Upstream() as up:
        up.routes["/ws"] = websocket_echo
        server, _ = make_gateway(up.port)
        with server as gw:
            with socket.create_connection(("127.0.0.1", gw.port), timeout=3) as s:
                s.settimeout(3)
                s.sendall(f"GET ws://app.test:{up.port}/ws HTTP/1.1\r\nHost: app.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
                          "Sec-WebSocket-Key: a\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
                head = b""
                while b"\r\n\r\n" not in head:
                    head += s.recv(4096)
                assert head.startswith(b"HTTP/1.1 101")
                s.sendall(b"ping")
                assert s.recv(4096) == b"ping"
