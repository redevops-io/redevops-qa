# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""SSRF vectors against the REAL gateway over loopback sockets: encodings, IPv6 forms, userinfo, ports, names, absolute-URI and
request-line forms, CONNECT, DNS answers and rebinding, redirects, hop-by-hop headers, oversized responses, WebSocket.

The upstream servers are on 127.0.0.1; every name is mapped by a scripted resolver; the policy lists the test network
(``private_ok``) for exactly the names the vectors use. A denied vector must also leave the upstream untouched.
"""
import socket
import time

import pytest
from agent_harness.qa.egress import AllowEntry, EgressPolicy
from qa_egress import GatewayLimits

from qa_eg_support import (RawUpstream, ScriptedResolver, Upstream, echo_headers, get, make_gateway, ok, private_entry, raw_request,
                           raw_response, redirect, stall, stream, websocket_echo)

PRIV_NETS = ("127.0.0.1/32", "10.0.0.0/24", "224.0.0.0/24", "0.0.0.0/24")
DNS_NAMES = ("meta.test", "meta6.test", "split.test", "split2.test", "mapped.test", "nat64.test", "sixtofour.test", "teredo.test",
             "outside.test", "empty.test", "err.test", "badstr.test", "badaddr1.test", "badaddr2.test", "badaddr3.test",
             "badaddr4.test", "badaddr5.test", "badaddr6.test", "many.test", "unspec.test", "multicast.test", "rebind.test")
PUBLIC_NAMES = ("pub.test", "pub10.test")

DNS_TABLE = {
    "app.test": [["127.0.0.1"]], "meta.test": [["169.254.169.254"]], "meta6.test": [["fd00:ec2::254"]],
    "split.test": [["127.0.0.1", "169.254.169.254"]], "split2.test": [["169.254.169.254", "127.0.0.1"]],
    "mapped.test": [["::ffff:127.0.0.1"]], "nat64.test": [["64:ff9b::7f00:1"]], "sixtofour.test": [["2002:7f00:1::"]],
    "teredo.test": [["2001:0:4136:e378:8000:63bf:3fff:fdd2"]], "outside.test": [["10.0.1.9"]], "empty.test": [[]],
    "err.test": [LookupError("nope")], "badstr.test": ["127.0.0.1"], "badaddr1.test": [["999.1.1.1"]],
    "badaddr2.test": [["127.0.0.1%eth0"]], "badaddr3.test": [[""]], "badaddr4.test": [[None]],
    "badaddr5.test": [["127.0.0.1 "]], "badaddr6.test": [[b"127.0.0.1"]],
    "many.test": [[f"10.0.0.{i}" for i in range(1, 18)]], "unspec.test": [["0.0.0.0"]], "multicast.test": [["224.0.0.1"]],
    "rebind.test": [["127.0.0.1"], ["169.254.169.254"]], "pub.test": [["127.0.0.1"]], "pub10.test": [["10.0.0.5"]],
}


@pytest.fixture(scope="module")
def env():
    with Upstream() as up:
        entries = [private_entry("app.test", up.port)]
        entries += [AllowEntry(host=n, networks=PRIV_NETS, schemes=("http", "ws"), ports=(up.port,), private_ok=True) for n in DNS_NAMES]
        entries += [AllowEntry(host=n, schemes=("http",), ports=(up.port,)) for n in PUBLIC_NAMES]
        resolver = ScriptedResolver({k: [list(a) if isinstance(a, list) else a for a in v] for k, v in DNS_TABLE.items()})
        server, _ = make_gateway(up.port, resolver, policy=EgressPolicy(entries=tuple(entries)))
        with server as gw:
            yield type("Env", (), {"up": up, "gw": gw, "resolver": resolver, "P": up.port})


def denied(r, *reasons):
    assert r.denied, (r.status, r.headers, r.body[:80])
    if reasons:
        assert r.reason in reasons, (r.reason, reasons)


def refused(r, status, code):
    assert (r.status, r.reason) == (status, code), (r.status, r.reason)
    assert not r.denied


def untouched(env, before):
    assert len(env.up.seen) == before


def via(env, url, **kw):
    before = len(env.up.seen)
    r = get(env.gw.port, url, **kw)
    return r, before


# ---- A. numeric encodings of loopback: the entry names a host, so a literal (in any spelling) is not listed ----------------------
LOOPBACK_SPELLINGS = ["2130706433", "0x7f000001", "0x7f.0.0.1", "0177.0.0.1", "017700000001", "127.1", "127.0.1", "0x7f.1",
                      "127.0x0.0.1", "0177.0.0.01", "127.00.00.01", "127.0.0.1", "127.0.0.1.", "[::1]", "[0:0:0:0:0:0:0:1]",
                      "[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "[0000::1]", "0", "0.0.0.0", "localhost", "LOCALHOST", "localhost.", "0xZZ"]


@pytest.mark.parametrize("host", LOOPBACK_SPELLINGS)
def test_loopback_in_any_spelling_is_not_listed(env, host):
    r, before = via(env, f"http://{host}:{env.P}/")
    denied(r, "DENY_NOT_LISTED")
    untouched(env, before)


@pytest.mark.parametrize("host", ["0x7g.0.0.1", "256.0.0.1", "1.2.3.4.5", "08.0.0.1", "0x100000000", "4294967296", "1.2.3.256",
                                  "127..1", ".127.0.0.1"])
def test_malformed_numeric_hosts_are_refused_as_host_syntax(env, host):
    r, before = via(env, f"http://{host}:{env.P}/")
    denied(r, "DENY_HOST_SYNTAX")
    untouched(env, before)


# ---- B. metadata and link-local, in every spelling the browser would reach ---------------------------------------------------
METADATA_HOSTS = ["169.254.169.254", "2852039166", "0xa9fea9fe", "0xA9.0xFE.0xA9.0xFE", "0251.0376.0251.0376", "169.254.43518",
                  "169.16689662", "0251.254.169.254", "[::ffff:169.254.169.254]", "[::ffff:a9fe:a9fe]", "[64:ff9b::a9fe:a9fe]",
                  "[2002:a9fe:a9fe::1]", "[fd00:ec2::254]", "[fd00:ec2:0:0:0:0:0:254]", "[FD00:EC2::254]", "[fe80::1]",
                  "[fe80::a9fe:a9fe]", "100.100.100.200", "168.63.129.16", "[fd20:ce::1]", "192.0.0.192", "169.254.0.1",
                  "169.254.169.253", "[::169.254.169.254]"]


@pytest.mark.parametrize("host", METADATA_HOSTS)
def test_metadata_and_link_local_in_any_spelling_are_refused(env, host):
    r, before = via(env, f"http://{host}/latest/meta-data/")
    denied(r, "DENY_METADATA_ADDRESS")
    untouched(env, before)


@pytest.mark.parametrize("host", ["169.254.169.254", "[fd00:ec2::254]", "2852039166", "100.100.100.200"])
def test_metadata_with_a_port_and_a_path_and_a_query_is_refused_and_the_query_is_not_kept(env, host):
    r, before = via(env, f"http://{host}:{env.P}/a/b?token=SENSITIVE")
    denied(r, "DENY_METADATA_ADDRESS")
    untouched(env, before)
    assert "SENSITIVE" not in repr(env.gw.events())


# ---- C. names that only mean "inside" --------------------------------------------------------------------------------------------
INTERNAL_NAMES = ["metadata.google.internal", "metadata", "instance-data", "instance-data.ec2.internal", "metadata.goog",
                  "foo.internal", "a.b.local", "x.localhost", "svc.localdomain", "printer.lan", "db.corp", "x.home.arpa",
                  "intra.intranet", "x.private", "METADATA.GOOGLE.INTERNAL", "metadata.google.internal.",
                  "metadata%2Egoogle%2Einternal", "metadata%E3%80%82google%E3%80%82internal",
                  "metadata%EF%BC%8Egoogle%EF%BC%8Einternal", "%EF%BD%8Detadata.google.internal", "%6Detadata.google.internal",
                  "foo.INTERNAL", "a.local."]


@pytest.mark.parametrize("name", INTERNAL_NAMES)
def test_metadata_and_internal_names_are_refused_even_when_nothing_else_is_wrong(env, name):
    r, before = via(env, f"http://{name}:{env.P}/")
    denied(r, "DENY_METADATA_NAME", "DENY_INTERNAL_NAME", "DENY_HOST_SYNTAX", "DENY_MALFORMED_URL")
    untouched(env, before)
    assert env.resolver.calls.count(name) == 0


def test_non_ascii_targets_are_refused_before_any_decision(env):
    for name in ("metadata。google。internal", "ｍetadata.google.internal", "app.tést", "münchen.test"):
        before = len(env.up.seen)
        r = raw_request(env.gw.port, f"GET http://{name}:{env.P}/ HTTP/1.1\r\nHost: x\r\n\r\n".encode("utf-8"))
        refused(r, 400, "NON_ASCII_TARGET")
        untouched(env, before)
    assert not [c for c in env.resolver.calls if not c.isascii()]


@pytest.mark.parametrize("name,reason", [("a%252Eb.test", "DENY_HOST_SYNTAX"), ("exa mple.test", "DENY_MALFORMED_URL"),
                                         ("a_b.test", "DENY_NOT_LISTED"), ("-a.test", "DENY_HOST_SYNTAX"),
                                         ("a..test", "DENY_HOST_SYNTAX"), ("a%00.test", "DENY_HOST_SYNTAX"),
                                         ("a%zz.test", "DENY_HOST_SYNTAX"), ("x" * 64 + ".test", "DENY_HOST_SYNTAX")])
def test_odd_names_are_refused(env, name, reason):
    r, before = via(env, f"http://{name}:{env.P}/")
    if " " in name:
        assert r.status == 400
    else:
        denied(r, reason)
    untouched(env, before)


# ---- D. userinfo -----------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("authority", ["user@app.test:{P}", "user:pw@app.test:{P}", "@app.test:{P}", "app.test:{P}@evil.test",
                                       "app.test@127.0.0.1:{P}", "%40@app.test:{P}", "a@b@app.test:{P}", "app.test:{P}@169.254.169.254",
                                       "user@[::1]:{P}", ":@app.test:{P}"])
def test_userinfo_in_any_form_is_refused(env, authority):
    r, before = via(env, "http://" + authority.format(P=env.P) + "/")
    denied(r, "DENY_USERINFO")
    untouched(env, before)


# ---- E. ports ---------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("port,reason", [("0", "DENY_PORT"), ("65536", "DENY_PORT"), ("99999", "DENY_PORT"), ("-1", "DENY_PORT"),
                                         ("abc", "DENY_PORT"), ("80x", "DENY_PORT"), ("0x50", "DENY_PORT"), ("+80", "DENY_PORT"),
                                         ("1e2", "DENY_PORT"), ("123456", "DENY_PORT"), ("", "DENY_NOT_LISTED"), ("80", "DENY_NOT_LISTED"),
                                         ("22", "DENY_NOT_LISTED"), ("{Q}", "DENY_NOT_LISTED")])
def test_ports_that_are_invalid_or_not_listed_are_refused(env, port, reason):
    r, before = via(env, f"http://app.test:{port.format(Q=env.P + 1)}/")
    denied(r, reason)
    untouched(env, before)


# ---- F. absolute-URI and request-line forms ------------------------------------------------------------------------------------
@pytest.mark.parametrize("line,status,code", [
    ("GET /x HTTP/1.1", 400, "NOT_A_PROXY_REQUEST"), ("GET * HTTP/1.1", 400, "NOT_A_PROXY_REQUEST"),
    ("OPTIONS * HTTP/1.1", 400, "NOT_A_PROXY_REQUEST"), ("GET //app.test/x HTTP/1.1", 400, "NOT_A_PROXY_REQUEST"),
    ("GET HTTP/1.1", 400, "MALFORMED_REQUEST_LINE"), ("GET  http://app.test/ HTTP/1.1", 400, "MALFORMED_REQUEST_LINE"),
    ("GET http://app.test/ HTTP/1.1 x", 400, "MALFORMED_REQUEST_LINE"), ("get http://app.test/ HTTP/1.1", 400, "MALFORMED_METHOD"),
    ("GéT http://app.test/ HTTP/1.1", 400, "MALFORMED_METHOD"), ("FOO http://app.test:{P}/ HTTP/1.1", 405, "METHOD_NOT_ALLOWED"),
    ("TRACE http://app.test:{P}/ HTTP/1.1", 405, "METHOD_NOT_ALLOWED"), ("PRI * HTTP/2.0", 505, "VERSION_NOT_SUPPORTED"),
    ("GET http://app.test:{P}/ HTTP/0.9", 505, "VERSION_NOT_SUPPORTED"), ("GET http://app.test:{P}/ HTTP/1.2", 505, "VERSION_NOT_SUPPORTED"),
    ("GET http://app.test:{P}/ HTTP/2", 505, "VERSION_NOT_SUPPORTED"), ("GET http://app.test:{P}/é HTTP/1.1", 400, "NON_ASCII_TARGET"),
    ("GET http://app.test:{P}/" + "a" * 3000 + " HTTP/1.1", 414, "URI_TOO_LONG"),
])
def test_request_line_forms_that_are_not_a_proxy_request_are_refused(env, line, status, code):
    before = len(env.up.seen)
    r = raw_request(env.gw.port, (line.format(P=env.P) + "\r\nHost: x\r\n\r\n").encode("utf-8"))
    refused(r, status, code)
    untouched(env, before)


@pytest.mark.parametrize("url,reason", [
    ("https://app.test/", "DENY_NOT_LISTED"), ("ftp://app.test/", "DENY_SCHEME"), ("file:///etc/passwd", "DENY_SCHEME"),
    ("gopher://app.test/", "DENY_SCHEME"), ("javascript:alert(1)", "DENY_SCHEME"), ("data:text/plain,hi", "DENY_SCHEME"),
    ("dict://app.test/", "DENY_SCHEME"), ("ldap://app.test/", "DENY_SCHEME"), ("blob:http://app.test/x", "DENY_SCHEME"),
    ("wss://app.test/", "DENY_NOT_LISTED"), ("http:/app.test/", "DENY_MALFORMED_URL"), ("http:app.test/", "DENY_MALFORMED_URL"),
    ("http:///app.test/", "DENY_HOST_SYNTAX"), ("http://", "DENY_HOST_SYNTAX"), ("http://:80/", "DENY_HOST_SYNTAX"),
    ("http:\\\\app.test\\x", "DENY_MALFORMED_URL"), ("http://app.test:{P}/\tx", "DENY_MALFORMED_URL"),
    ("http://app.test:{P}\\@evil.test/", "DENY_MALFORMED_URL"), ("http://[::1/", "DENY_HOST_SYNTAX"), ("http://[::1]x/", "DENY_HOST_SYNTAX"),
    ("http://::1/", "DENY_HOST_SYNTAX"), ("http://[fe80::1%25eth0]/", "DENY_HOST_SYNTAX"), ("http://[::g]/", "DENY_HOST_SYNTAX"),
    ("http://[]/", "DENY_HOST_SYNTAX"), ("1http://app.test/", "DENY_MALFORMED_URL"), ("://app.test/", "DENY_MALFORMED_URL"),
])
def test_url_forms_are_refused_by_the_policy_with_a_reason(env, url, reason):
    r, before = via(env, url.format(P=env.P))
    denied(r, reason)
    untouched(env, before)


def test_uppercase_scheme_and_host_and_a_missing_path_are_normalised_and_relayed(env):
    for url, path in ((f"HTTP://APP.TEST:{env.P}/up", "/up"), (f"http://app.test:{env.P}", "/"), (f"http://app.test.:{env.P}/dot", "/dot"),
                      (f"http://app.test:{env.P}?q=1", "/?q=1"), (f"http://app.test:{env.P}/f#frag", "/f")):
        before = len(env.up.seen)
        r = get(env.gw.port, url)
        assert r.status == 200, (url, r.status, r.reason)
        assert env.up.seen[before].request_line == f"GET {path} HTTP/1.1"


def test_https_in_a_plain_request_needs_connect_even_when_listed():
    with Upstream() as up:
        server, _ = make_gateway(up.port, policy=EgressPolicy(entries=(private_entry("app.test", up.port, schemes=("https", "wss")),)))
        with server as gw:
            refused(get(gw.port, f"https://app.test:{up.port}/"), 400, "USE_CONNECT")
            refused(get(gw.port, f"wss://app.test:{up.port}/"), 400, "USE_CONNECT")
            assert up.seen == []


def test_ws_without_an_upgrade_is_refused(env):
    refused(get(env.gw.port, f"ws://app.test:{env.P}/"), 400, "UPGRADE_REQUIRED")


@pytest.mark.parametrize("raw,status,code", [
    (b"GET http://app.test:{P}/ HTTP/1.1\nHost: x\n\n", 400, "TRUNCATED_HEAD"),
    (b"GET http://app.test:{P}/ HTTP/1.1\rHost: x\r\r", 400, "TRUNCATED_HEAD"),
    (b"GET http://app.test:{P}/ HTTP/1.1\r\nX: a\nInject: b\r\n\r\n", 400, "MALFORMED_HEAD"),
    (b"GET http://app.test:{P}/ HTTP/1.1\r\nX: a\x00b\r\n\r\n", 400, "MALFORMED_HEAD"),
    (b"GET http://app.test:{P}/\x00 HTTP/1.1\r\n\r\n", 400, "MALFORMED_HEAD"),
    (b"GET http://app.test:{P}/ HTTP/1.1\r\nBad Header: x\r\n\r\n", 400, "MALFORMED_HEADER"),
    (b"GET http://app.test:{P}/ HTTP/1.1\r\nX: a\r\n folded\r\n\r\n", 400, "MALFORMED_HEADER"),
    (b"GET http://app.test:{P}/ HTTP/1.1\r\nNoColon\r\n\r\n", 400, "MALFORMED_HEADER"),
    (b"GET http://app.test:{P}/ HTTP/1.1\r\n: empty\r\n\r\n", 400, "MALFORMED_HEADER"),
    (b"GET http://app.test:{P}/ HTTP/1.1\r\nX: a\x01b\r\n\r\n", 400, "MALFORMED_HEADER"),
    (b"GET http://app.test:{P}/ HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab", 400, "CONFLICTING_CONTENT_LENGTH"),
    (b"GET http://app.test:{P}/ HTTP/1.1\r\nContent-Length: -1\r\n\r\n", 400, "BAD_CONTENT_LENGTH"),
    (b"GET http://app.test:{P}/ HTTP/1.1\r\nContent-Length: 1e3\r\n\r\n", 400, "BAD_CONTENT_LENGTH"),
    (b"GET http://app.test:{P}/ HTTP/1.1\r\nContent-Length: 0x10\r\n\r\n", 400, "BAD_CONTENT_LENGTH"),
    (b"POST http://app.test:{P}/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 501, "TRANSFER_CODING_UNSUPPORTED"),
    (b"POST http://app.test:{P}/ HTTP/1.1\r\nTransfer-Encoding: x\r\nContent-Length: 4\r\n\r\nabcd", 501, "TRANSFER_CODING_UNSUPPORTED"),
    (b"GET http://app.test:{P}/ HTTP/1.1\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n", 400, "UPGRADE_UNSUPPORTED"),
    (b"GET http://app.test:{P}/ HTTP/1.1\r\nUpgrade: websocket\r\n\r\n", 400, "UPGRADE_UNSUPPORTED"),
    (b"POST http://app.test:{P}/ HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", 400, "UPGRADE_UNSUPPORTED"),
    (b"GET http://app.test:{P}/ HTTP/1.1\r\n\r\nGET http://app.test:{P}/two HTTP/1.1\r\n\r\n", 400, "PIPELINING_UNSUPPORTED"),
    (b"GET http://app.test:{P}/ HTTP/1.1\r\n", 400, "TRUNCATED_HEAD"),
])
def test_malformed_and_smuggling_shaped_requests_are_refused_and_never_forwarded(env, raw, status, code):
    before = len(env.up.seen)
    r = raw_request(env.gw.port, raw.replace(b"{P}", str(env.P).encode()), shutdown_write=True)
    refused(r, status, code)
    untouched(env, before)


def test_too_many_headers_and_too_large_a_head_are_refused(env):
    many = b"GET http://app.test:%d/ HTTP/1.1\r\n" % env.P + b"".join(b"X-%d: y\r\n" % i for i in range(150)) + b"\r\n"
    refused(raw_request(env.gw.port, many), 431, "TOO_MANY_HEADERS")
    big = b"GET http://app.test:%d/ HTTP/1.1\r\nX: " % env.P + b"y" * 40000 + b"\r\n\r\n"
    refused(raw_request(env.gw.port, big), 431, "HEADER_TOO_LARGE")


# ---- G. CONNECT --------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("authority,reasons", [
    ("169.254.169.254:80", ("DENY_METADATA_ADDRESS",)), ("169.254.169.254:443", ("DENY_METADATA_ADDRESS",)),
    ("metadata.google.internal:443", ("DENY_METADATA_NAME",)), ("metadata:443", ("DENY_METADATA_NAME",)),
    ("[fd00:ec2::254]:443", ("DENY_METADATA_ADDRESS",)), ("2852039166:443", ("DENY_METADATA_ADDRESS",)),
    ("0xa9fea9fe:443", ("DENY_METADATA_ADDRESS",)), ("[::ffff:a9fe:a9fe]:443", ("DENY_METADATA_ADDRESS",)),
    ("x.internal:443", ("DENY_INTERNAL_NAME",)), ("foo.local:443", ("DENY_INTERNAL_NAME",)),
    ("100.100.100.200:443", ("DENY_METADATA_ADDRESS",)), ("[fe80::1]:443", ("DENY_METADATA_ADDRESS",)),
    ("10.0.0.1:443", ("DENY_NOT_LISTED",)), ("127.0.0.1:22", ("DENY_NOT_LISTED",)), ("localhost:443", ("DENY_NOT_LISTED",)),
    ("[::1]:443", ("DENY_NOT_LISTED",)), ("192.168.1.1:443", ("DENY_NOT_LISTED",)), ("172.16.0.1:443", ("DENY_NOT_LISTED",)),
    ("0.0.0.0:443", ("DENY_NOT_LISTED",)), ("app.test:{P}", ("DENY_NOT_LISTED",)),   # listed for http only, not https
    ("app.test:0", ("DENY_PORT",)), ("app.test:65536", ("DENY_PORT",)), ("a@b:443", ("DENY_HOST_SYNTAX",)),
    ("a/b:443", ("DENY_HOST_SYNTAX",)),
])
def test_connect_to_metadata_private_unlisted_or_odd_targets_is_refused(env, authority, reasons):
    before = len(env.up.seen)
    r = raw_request(env.gw.port, f"CONNECT {authority.format(P=env.P)} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    denied(r, *reasons)
    untouched(env, before)


@pytest.mark.parametrize("authority", ["app.test", ":443", "app.test:abc", "http://app.test:80", "/x", "::1:443", "[::1:443", "[::1]443",
                                       "app.test:443:443", "app.test:", "[]:443"])
def test_connect_with_a_malformed_authority_is_a_bad_request(env, authority):
    r = raw_request(env.gw.port, f"CONNECT {authority} HTTP/1.1\r\n\r\n".encode())
    refused(r, 400, "BAD_AUTHORITY")


# ---- H. DNS answers ----------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name,reason", [
    ("pub.test", "DENY_ADDRESS_NOT_PUBLIC"), ("pub10.test", "DENY_ADDRESS_NOT_PUBLIC"), ("meta.test", "DENY_METADATA_ADDRESS"),
    ("meta6.test", "DENY_METADATA_ADDRESS"), ("split.test", "DENY_METADATA_ADDRESS"), ("split2.test", "DENY_METADATA_ADDRESS"),
    ("mapped.test", "DENY_ADDRESS_MAPPED"), ("nat64.test", "DENY_ADDRESS_TRANSITION"), ("sixtofour.test", "DENY_ADDRESS_TRANSITION"),
    ("teredo.test", "DENY_ADDRESS_TRANSITION"), ("outside.test", "DENY_ADDRESS_OUTSIDE_ENTRY"), ("empty.test", "DENY_NO_ADDRESSES"),
    ("err.test", "DENY_RESOLVER_ERROR"), ("badstr.test", "DENY_RESOLVER_BAD_ANSWER"), ("badaddr1.test", "DENY_RESOLVER_BAD_ANSWER"),
    ("badaddr2.test", "DENY_RESOLVER_BAD_ANSWER"), ("badaddr3.test", "DENY_RESOLVER_BAD_ANSWER"),
    ("badaddr4.test", "DENY_RESOLVER_BAD_ANSWER"), ("badaddr5.test", "DENY_RESOLVER_BAD_ANSWER"),
    ("badaddr6.test", "DENY_RESOLVER_BAD_ANSWER"), ("many.test", "DENY_TOO_MANY_ADDRESSES"),
    ("unspec.test", "DENY_ADDRESS_NOT_PUBLIC"), ("multicast.test", "DENY_ADDRESS_NOT_PUBLIC"),
])
def test_a_listed_name_whose_answer_is_unacceptable_is_refused_and_the_upstream_is_never_contacted(env, name, reason):
    r, before = via(env, f"http://{name}:{env.P}/")
    denied(r, reason)
    untouched(env, before)
    assert env.resolver.calls.count(name) >= 1


def test_dns_rebinding_the_first_answer_is_pinned_and_a_later_different_answer_is_a_new_decision(env):
    env.resolver.set("rebind.test", ["127.0.0.1"], ["169.254.169.254"])
    before_calls = env.resolver.calls.count("rebind.test")
    before = len(env.up.seen)
    first = get(env.gw.port, f"http://rebind.test:{env.P}/one")
    assert first.status == 200 and env.up.seen[before].headers["host"] == f"rebind.test:{env.P}"
    assert env.resolver.calls.count("rebind.test") - before_calls == 1               # resolved once for that request
    second = get(env.gw.port, f"http://rebind.test:{env.P}/two")
    denied(second, "DENY_METADATA_ADDRESS")
    assert len(env.up.seen) == before + 1


def test_a_name_is_resolved_exactly_once_per_request_whatever_it_answers(env):
    env.resolver.set("app.test", ["127.0.0.1"])
    calls = env.resolver.calls.count("app.test")
    for _ in range(3):
        assert get(env.gw.port, f"http://app.test:{env.P}/x").status == 200
    assert env.resolver.calls.count("app.test") - calls == 3


# ---- I. redirects ---------------------------------------------------------------------------------------------------------------------
REDIRECT_DENIED = [
    ("http://169.254.169.254/latest/meta-data/", "DENY_METADATA_ADDRESS"), ("http://[fd00:ec2::254]/", "DENY_METADATA_ADDRESS"),
    ("http://metadata.google.internal/", "DENY_METADATA_NAME"), ("http://2852039166/", "DENY_METADATA_ADDRESS"),
    ("//169.254.169.254/", "DENY_METADATA_ADDRESS"), ("http://127.0.0.1:{P}/", "DENY_NOT_LISTED"),
    ("http://localhost:{P}/", "DENY_NOT_LISTED"), ("http://10.0.0.1/", "DENY_NOT_LISTED"), ("http://other.test:{P}/", "DENY_NOT_LISTED"),
    ("http://app.test:{Q}/", "DENY_NOT_LISTED"), ("http://user@app.test:{P}/", "DENY_USERINFO"), ("file:///etc/passwd", "DENY_SCHEME"),
    ("javascript:alert(1)", "DENY_SCHEME"), ("data:text/html,x", "DENY_SCHEME"), ("ftp://app.test/", "DENY_SCHEME"),
    ("gopher://x/", "DENY_SCHEME"), ("http://app.test:{P}/a b", "DENY_REDIRECT_LOCATION"),
    ("http:\\\\evil.test", "DENY_REDIRECT_LOCATION"), ("http://app.test:{P}/" + "a" * 3000, "DENY_REDIRECT_LOCATION"),
    ("//10.0.0.1/", "DENY_NOT_LISTED"), ("http://meta.test:{P}/", "DENY_METADATA_ADDRESS"), ("http://pub.test:{P}/", "DENY_ADDRESS_NOT_PUBLIC"),
    ("http://[::1]:{P}/", "DENY_NOT_LISTED"), ("http://0x7f.1:{P}/", "DENY_NOT_LISTED"), ("//evil.test/", "DENY_NOT_LISTED"),
]


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_every_redirect_status_to_metadata_is_refused_before_the_client_sees_it(env, code):
    env.up.routes["/rd"] = redirect("http://169.254.169.254/", code)
    r, before = via(env, f"http://app.test:{env.P}/rd")
    assert r.denied and "location" not in r.headers and b"169.254" not in r.raw
    assert len(env.up.seen) == before + 1                                                     # the first hop was asked, the second never


@pytest.mark.parametrize("location,reason", REDIRECT_DENIED)
def test_a_redirect_whose_target_is_not_allowed_is_refused_per_hop(env, location, reason):
    env.up.routes["/rd"] = redirect(location.format(P=env.P, Q=env.P + 1))
    r, before = via(env, f"http://app.test:{env.P}/rd")
    assert r.status == 403 and r.denied and r.reason == reason and "location" not in r.headers
    assert len(env.up.seen) == before + 1


@pytest.mark.parametrize("data,reason", [
    (b"HTTP/1.1 302 Found\r\nLocation:\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", "DENY_REDIRECT_LOCATION"),
    (b"HTTP/1.1 302 Found\r\nLocation: http://app.test/a\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\n\r\n",
     "DENY_REDIRECT_LOCATION"),
])
def test_an_empty_or_repeated_location_is_refused(env, data, reason):
    env.up.routes["/rd"] = raw_response(data)
    r, _ = via(env, f"http://app.test:{env.P}/rd")
    assert r.denied and r.reason == reason


@pytest.mark.parametrize("location", ["/next", "http://app.test:{P}/next", "//app.test:{P}/next", "next", "?q=1", "http://APP.test:{P}/next"])
def test_a_redirect_to_the_same_listed_origin_is_relayed_unchanged(env, location):
    env.up.routes["/rd"] = redirect(location.format(P=env.P))
    r, _ = via(env, f"http://app.test:{env.P}/rd")
    assert r.status == 302 and r.headers["location"] == location.format(P=env.P)


def test_a_redirect_status_without_a_location_is_relayed_as_is(env):
    env.up.routes["/rd"] = raw_response(b"HTTP/1.1 302 Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
    r, _ = via(env, f"http://app.test:{env.P}/rd")
    assert r.status == 302 and r.body == b"hi"


def test_a_redirect_chain_is_cut_after_the_policys_redirect_limit(env):
    for i in range(0, 12):
        env.up.routes[f"/c{i}"] = redirect(f"http://app.test:{env.P}/c{i + 1}")
    url = f"http://app.test:{env.P}/c0"
    hops = 0
    while True:
        r = get(env.gw.port, url)
        if r.status != 302:
            break
        hops += 1
        url = r.headers["location"]
        assert hops < 12
    assert r.denied and r.reason == "DENY_REDIRECT_LIMIT" and hops == 5


def test_a_redirect_loop_to_itself_ends_in_the_same_limit(env):
    env.up.routes["/loop"] = redirect(f"http://app.test:{env.P}/loop")
    seen = 0
    r = get(env.gw.port, f"http://app.test:{env.P}/loop")
    while r.status == 302:
        seen += 1
        r = get(env.gw.port, r.headers["location"])
        assert seen < 20
    assert r.denied and r.reason == "DENY_REDIRECT_LIMIT"


# ---- J. hop-by-hop and request headers -------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["Proxy-Authorization", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Anything", "TE", "Trailer",
                                  "Keep-Alive", "Upgrade-Insecure-Requests-Not", "Expect"])
def test_hop_by_hop_and_proxy_headers_are_not_forwarded(env, name):
    env.up.routes["/echo"] = echo_headers
    r, before = via(env, f"http://app.test:{env.P}/echo", headers=[(name, "v1")])
    forwarded = r.body.decode("latin-1").lower()
    if name == "Upgrade-Insecure-Requests-Not":
        assert "upgrade-insecure-requests-not: v1" in forwarded          # an end-to-end header with a similar name is kept
    else:
        assert f"{name.lower()}: v1" not in forwarded


def test_headers_named_by_connection_are_dropped_and_the_host_comes_from_the_decided_url(env):
    env.up.routes["/echo"] = echo_headers
    r, _ = via(env, f"http://app.test:{env.P}/echo", headers=[("Host", "169.254.169.254"), ("Connection", "X-A, keep-alive"),
                                                           ("X-A", "1"), ("X-B", "2"), ("Cookie", "k=v"), ("Authorization", "Bearer abc")])
    text = r.body.decode("latin-1").lower()
    assert f"host: app.test:{env.P}" in text and "169.254" not in text and "x-a:" not in text and "x-b: 2" in text
    assert "cookie: k=v" in text and "authorization: bearer abc" in text          # end-to-end headers reach the origin


def test_the_connection_header_to_the_origin_is_close_and_there_is_one_request_per_connection(env):
    env.up.routes["/echo"] = echo_headers
    r, _ = via(env, f"http://app.test:{env.P}/echo", headers=[("Connection", "keep-alive")])
    assert "connection: close" in r.body.decode("latin-1").lower()


def test_a_request_body_is_forwarded_exactly(env):
    env.up.routes["/post"] = ok("posted")
    before = len(env.up.seen)
    r = get(env.gw.port, f"http://app.test:{env.P}/post", method="POST", body=b"a=1&b=2")
    assert r.status == 200 and env.up.seen[before].body == b"a=1&b=2"


# ---- K. oversized responses and misbehaving upstreams ---------------------------------------------------------------------------
@pytest.fixture()
def small(request):
    with Upstream() as up:
        limits = GatewayLimits(max_response_bytes=64 * 1024, max_response_header_bytes=4096, max_request_body_bytes=1024, read_timeout_s=1.0,
                               connect_timeout_s=2.0, dns_timeout_s=2.0, upstream_header_timeout_s=1.0, idle_timeout_s=1.0, total_timeout_s=4.0,
                               tunnel_total_timeout_s=4.0, max_tunnel_bytes=32 * 1024)
        server, _ = make_gateway(up.port, limits=limits)
        with server as gw:
            yield up, gw


def test_a_response_that_declares_too_much_is_refused_before_a_byte_of_it_is_relayed(small):
    up, gw = small
    up.routes["/big"] = stream(10 * 1024 * 1024, True)
    r = get(gw.port, f"http://app.test:{up.port}/big")
    assert (r.status, r.reason) == (502, "RESPONSE_TOO_LARGE") and len(r.raw) < 2048


def test_a_response_with_no_length_is_cut_at_the_bound(small):
    up, gw = small
    up.routes["/big"] = stream(10 * 1024 * 1024, False)
    r = get(gw.port, f"http://app.test:{up.port}/big")
    assert r.status == 200 and len(r.body) <= 64 * 1024
    gw.wait_idle()
    assert gw.counts()["limit_response_bytes"] == 1


def test_a_chunked_response_is_counted_with_its_framing_and_cut_at_the_bound(small):
    up, gw = small
    piece = b"%x\r\n" % 4096 + b"y" * 4096 + b"\r\n"
    up.routes["/chunked"] = raw_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + piece * 200)
    r = get(gw.port, f"http://app.test:{up.port}/chunked")
    assert r.status == 200 and len(r.body) <= 64 * 1024 and r.headers.get("transfer-encoding") == "chunked"


def test_an_oversized_upstream_head_is_refused(small):
    up, gw = small
    up.routes["/h"] = raw_response(b"HTTP/1.1 200 OK\r\nX: " + b"a" * 10000 + b"\r\nContent-Length: 0\r\n\r\n")
    r = get(gw.port, f"http://app.test:{up.port}/h")
    assert (r.status, r.reason) == (502, "UPSTREAM_HEADER_TOO_LARGE")


def test_a_silent_upstream_is_a_gateway_timeout(small):
    up, gw = small
    up.routes["/slow"] = stall(2.5)
    started = time.monotonic()
    r = get(gw.port, f"http://app.test:{up.port}/slow")
    assert (r.status, r.reason) == (504, "UPSTREAM_TIMEOUT") and time.monotonic() - started < 3


@pytest.mark.parametrize("data", [b"", b"garbage\r\n\r\n", b"HTTP/1.1 99 x\r\n\r\n", b"HTTP/2 200 OK\r\n\r\n", b"HTTP/1.1 100 Continue\r\n\r\n",
                                  b"HTTP/1.1 20 OK\r\n\r\n", b"HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
                                  b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n", b"HTTP/1.1 200 OK\r\nX: a\x00b\r\n\r\n"])
def test_a_malformed_or_closed_upstream_answer_is_a_bad_gateway_never_relayed_raw(small, data):
    up, gw = small
    up.routes["/m"] = raw_response(data)
    r = get(gw.port, f"http://app.test:{up.port}/m")
    assert r.status == 502 and b"garbage" not in r.raw


def test_the_status_text_of_the_upstream_is_replaced_when_it_is_not_plain(small):
    up, gw = small
    up.routes["/r"] = raw_response(b"HTTP/1.1 200 \xff\xfeodd\r\nContent-Length: 0\r\n\r\n")
    r = get(gw.port, f"http://app.test:{up.port}/r")
    assert r.status == 200 and r.raw.startswith(b"HTTP/1.1 200 OK\r\n")


def test_a_request_body_over_the_bound_is_refused_before_anything_is_forwarded(small):
    up, gw = small
    r = get(gw.port, f"http://app.test:{up.port}/p", method="POST", body=b"x" * 4096)
    assert (r.status, r.reason) == (413, "REQUEST_TOO_LARGE") and up.seen == []


def test_the_oversized_headers_of_a_response_carry_no_set_cookie_filtering_but_hop_headers_are_removed(small):
    up, gw = small
    up.routes["/r"] = raw_response(b"HTTP/1.1 200 OK\r\nProxy-Authenticate: x\r\nKeep-Alive: 5\r\nConnection: close, X-Y\r\nX-Y: 1\r\nSet-Cookie: a=b\r\nContent-Length: 0\r\n\r\n")
    r = get(gw.port, f"http://app.test:{up.port}/r")
    assert "proxy-authenticate" not in r.headers and "keep-alive" not in r.headers and "x-y" not in r.headers
    assert r.headers["set-cookie"] == "a=b" and r.headers["connection"] == "close"


# ---- L. WebSocket ---------------------------------------------------------------------------------------------------------------------
UPGRADE = "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: a\r\nSec-WebSocket-Version: 13\r\n"


@pytest.mark.parametrize("target,reason", [
    ("ws://other.test:{P}/ws", "DENY_NOT_LISTED"), ("ws://169.254.169.254/ws", "DENY_METADATA_ADDRESS"), ("ws://[fd00:ec2::254]/ws", "DENY_METADATA_ADDRESS"),
    ("ws://127.0.0.1:{P}/ws", "DENY_NOT_LISTED"), ("ws://localhost:{P}/ws", "DENY_NOT_LISTED"), ("ws://user@app.test:{P}/ws", "DENY_USERINFO"),
    ("ws://app.test:{Q}/ws", "DENY_NOT_LISTED"), ("http://other.test:{P}/ws", "DENY_NOT_LISTED"), ("ws://metadata.google.internal/ws", "DENY_METADATA_NAME"),
    ("ws://meta.test:{P}/ws", "DENY_METADATA_ADDRESS"),
])
def test_a_websocket_upgrade_to_an_unlisted_or_forbidden_target_is_refused(env, target, reason):
    before = len(env.up.seen)
    r = raw_request(env.gw.port, f"GET {target.format(P=env.P, Q=env.P + 1)} HTTP/1.1\r\nHost: x\r\n{UPGRADE}\r\n".encode())
    denied(r, reason)
    untouched(env, before)


def test_a_websocket_upgrade_through_an_http_absolute_uri_is_judged_as_ws_and_relayed(env):
    env.up.routes["/ws"] = websocket_echo
    with socket.create_connection(("127.0.0.1", env.gw.port), timeout=3) as s:
        s.settimeout(3)
        s.sendall(f"GET http://app.test:{env.P}/ws HTTP/1.1\r\nHost: x\r\n{UPGRADE}\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += s.recv(4096)
        assert head.startswith(b"HTTP/1.1 101") and b"Upgrade: websocket" in head
        s.sendall(b"hello")
        assert s.recv(4096) == b"hello"


def test_a_refused_upgrade_answer_from_the_origin_is_relayed_as_an_ordinary_response(env):
    env.up.routes["/nows"] = ok("no", status="403 Forbidden")
    r = raw_request(env.gw.port, f"GET ws://app.test:{env.P}/nows HTTP/1.1\r\nHost: x\r\n{UPGRADE}\r\n".encode())
    assert r.status == 403 and r.body == b"no" and "x-egress-decision" not in r.headers


# ---- M. caps and timeouts -------------------------------------------------------------------------------------------------------------
def test_a_slow_head_is_cut_at_the_read_timeout(small):
    up, gw = small
    with socket.create_connection(("127.0.0.1", gw.port), timeout=4) as s:
        s.settimeout(4)
        s.sendall(b"GET http://app.test:1/ HTTP/1.1\r\nHost: ")
        started = time.monotonic()
        data = s.recv(4096)
    assert b" 408 " in data.split(b"\r\n", 1)[0] and time.monotonic() - started < 3


def test_connections_beyond_the_cap_are_answered_503(small):
    up, gw = small
    limits = GatewayLimits(max_connections=2, read_timeout_s=3.0)
    server, _ = make_gateway(up.port, limits=limits)
    with server as gateway:
        held = [socket.create_connection(("127.0.0.1", gateway.port), timeout=3) for _ in range(2)]
        time.sleep(0.2)
        r = raw_request(gateway.port, b"GET http://app.test:1/ HTTP/1.1\r\n\r\n")
        for sock in held:
            sock.close()
        assert (r.status, r.reason) == (503, "OVER_CAPACITY")
        gateway.wait_idle()
        assert gateway.counts()["limit_connections"] >= 1


def test_a_tunnel_is_cut_at_the_byte_bound():
    with RawUpstream("echo") as raw:
        server, _ = make_gateway(raw.port, policy=EgressPolicy(entries=(private_entry("app.test", raw.port, schemes=("https",)),)),
                                 limits=GatewayLimits(max_tunnel_bytes=8 * 1024, idle_timeout_s=2.0, tunnel_total_timeout_s=5.0))
        with server as gateway:
            with socket.create_connection(("127.0.0.1", gateway.port), timeout=3) as s:
                s.settimeout(3)
                s.sendall(f"CONNECT app.test:{raw.port} HTTP/1.1\r\n\r\n".encode())
                assert s.recv(4096).startswith(b"HTTP/1.1 200")
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
            gateway.wait_idle()
            assert 0 < got <= 8 * 1024 and gateway.counts()["limit_tunnel_bytes"] == 1


def test_an_idle_tunnel_is_closed_at_the_idle_bound():
    with RawUpstream("silent") as raw:
        server, _ = make_gateway(raw.port, policy=EgressPolicy(entries=(private_entry("app.test", raw.port, schemes=("https",)),)),
                                 limits=GatewayLimits(idle_timeout_s=0.5, tunnel_total_timeout_s=5.0))
        with server as gateway:
            with socket.create_connection(("127.0.0.1", gateway.port), timeout=3) as s:
                s.settimeout(4)
                s.sendall(f"CONNECT app.test:{raw.port} HTTP/1.1\r\n\r\n".encode())
                assert s.recv(4096).startswith(b"HTTP/1.1 200")
                started = time.monotonic()
                assert s.recv(4096) == b""
                assert time.monotonic() - started < 3
            gateway.wait_idle()
            assert gateway.counts()["limit_idle_timeout"] == 1


def test_a_tunnel_is_cut_at_the_total_bound():
    with RawUpstream("silent") as raw:
        server, _ = make_gateway(raw.port, policy=EgressPolicy(entries=(private_entry("app.test", raw.port, schemes=("https",)),)),
                                 limits=GatewayLimits(idle_timeout_s=30.0, tunnel_total_timeout_s=0.6))
        with server as gateway:
            with socket.create_connection(("127.0.0.1", gateway.port), timeout=3) as s:
                s.settimeout(4)
                s.sendall(f"CONNECT app.test:{raw.port} HTTP/1.1\r\n\r\n".encode())
                assert s.recv(4096).startswith(b"HTTP/1.1 200")
                assert s.recv(4096) == b""
            gateway.wait_idle()
            assert gateway.counts()["limit_total_timeout"] == 1


# ---- N. without the test network entry, everything is refused ---------------------------------------------------------------------
@pytest.mark.parametrize("name", ["app.test", "other.test", "127.0.0.1", "localhost", "[::1]", "10.0.0.5", "pub.test", "meta.test",
                                  "169.254.169.254", "metadata.google.internal"])
def test_with_no_private_entry_every_destination_is_refused(name):
    with Upstream() as up:
        public_only = EgressPolicy(entries=(AllowEntry(host="app.test", schemes=("http",), ports=(up.port,)),
                                            AllowEntry(host="pub.test", schemes=("http",), ports=(up.port,))))
        server, _ = make_gateway(up.port, ScriptedResolver({"app.test": [["127.0.0.1"]], "pub.test": [["127.0.0.1"]],
                                                           "meta.test": [["169.254.169.254"]]}), policy=public_only)
        with server as gw:
            r = get(gw.port, f"http://{name}:{up.port}/")
            assert r.denied
            assert up.seen == []


def test_an_empty_policy_refuses_everything_and_resolves_nothing():
    with Upstream() as up:
        resolver = ScriptedResolver({"app.test": [["127.0.0.1"]]})
        server, _ = make_gateway(up.port, resolver, policy=EgressPolicy(entries=()))
        with server as gw:
            for url in (f"http://app.test:{up.port}/", f"http://127.0.0.1:{up.port}/", "http://example.org/"):
                r = get(gw.port, url)
                assert r.denied and r.reason == "DENY_NOT_LISTED"
            r = raw_request(gw.port, b"CONNECT app.test:443 HTTP/1.1\r\n\r\n")
            assert r.denied
            assert up.seen == [] and resolver.calls == []
