# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Clean shutdown, resource bounds and configuration checks."""
import os
import socket
import threading
import time

import pytest
from agent_harness.qa.egress import EgressPolicy
from qa_egress import EgressGateway, GatewayLimits, GatewayServer

from qa_eg_support import RawUpstream, ScriptedResolver, Upstream, get, make_gateway, ok, private_entry


def open_fds():
    return len(os.listdir("/dev/fd"))


def test_stop_closes_the_listener_the_connections_the_tasks_and_the_thread():
    with Upstream() as up:
        server, _ = make_gateway(up.port)
        server.start()
        port = server.port
        assert get(port, f"http://app.test:{up.port}/").status == 200
        server.wait_idle()
        thread = server._thread
        server.stop()
        assert not thread.is_alive()
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
        gateway = server.gateway
        assert gateway.active_connections == 0 and not gateway._tasks and not gateway._writers and gateway._server is None


def test_stopping_mid_tunnel_ends_both_sides_and_leaks_nothing():
    with RawUpstream("echo") as raw:
        policy = EgressPolicy(entries=(private_entry("app.test", raw.port, schemes=("https",)),))
        server, _ = make_gateway(raw.port, policy=policy)
        server.start()
        before = open_fds()
        s = socket.create_connection(("127.0.0.1", server.port), timeout=3)
        s.settimeout(3)
        s.sendall(f"CONNECT app.test:{raw.port} HTTP/1.1\r\n\r\n".encode())
        assert s.recv(4096).startswith(b"HTTP/1.1 200")
        s.sendall(b"hi")
        assert s.recv(10) == b"hi"
        server.stop()
        assert s.recv(10) == b""                 # the client sees the tunnel end
        s.close()
        gateway = server.gateway
        assert not gateway._writers and not gateway._tasks
        time.sleep(0.1)
        assert open_fds() <= before


def test_a_gateway_that_served_many_requests_leaves_no_descriptor_behind():
    with Upstream() as up:
        # warm up, then compare: starting, serving and stopping must return the process to the same number of descriptors
        server, _ = make_gateway(up.port)
        with server as gw:
            get(gw.port, f"http://app.test:{up.port}/")
            gw.wait_idle()
        time.sleep(0.2)
        before = open_fds()
        server2, _ = make_gateway(up.port)
        with server2 as gw2:
            for i in range(20):
                get(gw2.port, f"http://app.test:{up.port}/{i}")
                get(gw2.port, "http://169.254.169.254/")
            gw2.wait_idle()
        time.sleep(0.3)
        assert open_fds() <= before


def test_stop_is_idempotent_and_safe_before_start():
    server = GatewayServer(EgressPolicy(entries=()), ScriptedResolver())
    server.stop()
    server.start()
    server.stop()
    server.stop()


def test_the_server_reports_a_start_failure_instead_of_hanging():
    with Upstream() as up:
        server, _ = make_gateway(up.port)
        with server as first:
            clash = GatewayServer(EgressPolicy(entries=()), ScriptedResolver(), port=first.port)
            with pytest.raises(OSError):
                clash.start(timeout=5)


def test_the_gateway_binds_loopback_unless_told_otherwise():
    with Upstream() as up:
        server, _ = make_gateway(up.port)
        with server as gw:
            host, port = gw.gateway._server.sockets[0].getsockname()[:2]
            assert host == "127.0.0.1" and port == gw.port


def test_a_burst_of_connections_is_bounded_and_every_one_is_answered_or_closed():
    with Upstream() as up:
        up.default = ok("hello")
        server, _ = make_gateway(up.port, limits=GatewayLimits(max_connections=4, read_timeout_s=1.0, idle_timeout_s=1.0, total_timeout_s=3.0))
        with server as gw:
            results = []

            def hit():
                results.append(get(gw.port, f"http://app.test:{up.port}/").status)
            threads = [threading.Thread(target=hit) for _ in range(30)]
            [t.start() for t in threads]
            [t.join(8) for t in threads]
            assert len(results) == 30 and set(results) <= {200, 503}
            gw.wait_idle()
            assert gw.active_connections() == 0


@pytest.mark.parametrize("name,value", [("max_header_bytes", 10), ("max_connections", 0), ("read_timeout_s", 0), ("idle_timeout_s", -1),
                                        ("max_response_bytes", 0), ("max_records", 0), ("dns_timeout_s", 10000), ("max_uri_chars", True),
                                        ("total_timeout_s", "5"), ("max_tunnel_bytes", None)])
def test_a_limit_outside_its_range_is_refused_not_clamped(name, value):
    with pytest.raises(ValueError):
        GatewayLimits(**{name: value})


def test_limits_from_configuration_refuses_unknown_keys():
    assert GatewayLimits.from_config({"max_connections": 3}).max_connections == 3
    with pytest.raises(ValueError):
        GatewayLimits.from_config({"max_everything": 1})


def test_every_default_limit_is_finite_and_small_enough_for_a_test_browser():
    limits = GatewayLimits()
    assert limits.max_connections <= 64 and limits.max_response_bytes <= 8 << 20 and limits.total_timeout_s <= 30
    assert limits.max_tunnel_bytes <= 16 << 20 and limits.max_header_bytes <= 16 * 1024


def test_the_operator_configuration_builds_a_policy_and_limits():
    from qa_egress.__main__ import main
    from agent_harness.qa.egress import EgressPolicy
    policy = EgressPolicy.from_config({"allow": ["https://example.org"], "private": [{"host": "app", "networks": ["10.0.0.0/24"],
                                                                                    "schemes": ["http"], "ports": [8080]}]})
    assert len(policy.entries) == 2 and callable(main)
