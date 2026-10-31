# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The browser launch configuration: the exact flag set, a golden file, and the loopback-is-not-bypassed semantics."""
import json
from pathlib import Path

import pytest
from qa_egress import (CONTEXT_OPTIONS, FORBIDDEN_PREFIXES, LOOPBACK_NOT_BYPASSED, build_launch_config, policy_off_config)

GOLDEN = Path(__file__).resolve().parent / "golden" / "launch_config.json"

EXACT_FLAGS = [
    "--proxy-server=http://127.0.0.1:18080",
    "--proxy-bypass-list=<-loopback>",
    "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
    "--disable-quic",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--dns-prefetch-disable",
    "--no-pings",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-domain-reliability",
    "--disable-client-side-phishing-detection",
    "--disable-sync",
    "--disable-default-apps",
    "--disable-extensions",
    "--disable-component-extensions-with-background-pages",
    "--block-new-web-contents",
    "--deny-permission-prompts",
    "--no-first-run",
    "--no-default-browser-check",
]


def test_the_flag_set_is_exactly_this():
    assert list(build_launch_config("127.0.0.1", 18080).chromium_args) == EXACT_FLAGS


def test_the_configuration_equals_the_golden_file_byte_for_byte():
    cfg = build_launch_config("127.0.0.1", 18080)
    assert cfg.golden_text() == GOLDEN.read_text(encoding="utf-8")
    assert json.loads(GOLDEN.read_text(encoding="utf-8")) == cfg.to_json()


def test_loopback_and_private_destinations_are_not_bypassed():
    cfg = build_launch_config("127.0.0.1", 18080)
    bypass = [a for a in cfg.chromium_args if a.startswith("--proxy-bypass-list=")]
    assert bypass == ["--proxy-bypass-list=" + LOOPBACK_NOT_BYPASSED] and LOOPBACK_NOT_BYPASSED == "<-loopback>"
    assert cfg.playwright_proxy == {"server": "http://127.0.0.1:18080", "bypass": "<-loopback>"}
    # the only bypass entry is the one that REMOVES the implicit loopback rule: no host, domain or range is ever bypassed
    value = bypass[0].split("=", 1)[1]
    assert value.split(";") == ["<-loopback>"]
    assert "localhost" not in value and "127." not in value and "10." not in value and "*" not in value


def test_every_destination_goes_to_the_proxy_and_the_browser_resolves_no_name_itself():
    args = build_launch_config("127.0.0.1", 18080).chromium_args
    assert sum(a.startswith("--proxy-server=") for a in args) == 1
    assert "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" in args
    assert not [a for a in args if a.startswith(("--proxy-pac-url", "--proxy-auto-detect", "--no-proxy-server"))]


@pytest.mark.parametrize("flag", ["--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--dns-prefetch-disable",
                                  "--no-pings", "--disable-background-networking", "--disable-component-update", "--disable-sync",
                                  "--disable-extensions", "--block-new-web-contents", "--deny-permission-prompts"])
def test_each_side_channel_flag_is_present(flag):
    assert flag in build_launch_config("127.0.0.1", 18080).chromium_args


def test_the_context_options_block_downloads_and_service_workers_and_grant_nothing():
    opts = build_launch_config("127.0.0.1", 18080).context_options
    assert opts["accept_downloads"] is False and opts["service_workers"] == "block" and opts["permissions"] == []
    assert opts["ignore_https_errors"] is False and opts["bypass_csp"] is False
    assert dict(opts) == dict(CONTEXT_OPTIONS)


def test_the_gateway_address_is_written_in_every_place_it_appears():
    cfg = build_launch_config("10.1.2.3", 3128)
    assert cfg.proxy_server == "http://10.1.2.3:3128" and cfg.chromium_args[0] == "--proxy-server=http://10.1.2.3:3128"
    assert "EXCLUDE 10.1.2.3" in cfg.chromium_args[2]
    v6 = build_launch_config("::1", 3128)
    assert v6.proxy_server == "http://[::1]:3128" and "EXCLUDE ::1" in v6.chromium_args[2]
    named = build_launch_config("qa-egress", 3128)
    assert named.proxy_server == "http://qa-egress:3128"


@pytest.mark.parametrize("host", ["", "a b", "Example.COM", "a/b", "a@b", "a:b", "[::1]", "-x", "x" * 300, "a..b", "http://x"])
def test_a_gateway_host_that_is_not_an_address_or_a_plain_name_is_refused(host):
    with pytest.raises(ValueError):
        build_launch_config(host, 3128)


@pytest.mark.parametrize("port", [0, -1, 65536, "3128", None, 3128.0, True])
def test_a_bad_gateway_port_is_refused(port):
    with pytest.raises(ValueError):
        build_launch_config("127.0.0.1", port)


@pytest.mark.parametrize("extra", ["--proxy-server=http://evil:1", "--proxy-bypass-list=*", "--proxy-pac-url=http://x/p.pac",
                                   "--proxy-auto-detect", "--no-proxy-server", "--host-resolver-rules=MAP * 1.2.3.4",
                                   "--enable-quic", "--webrtc-ip-handling-policy=default", "--enable-features=NetworkService",
                                   "--disable-features=X", "--disable-web-security", "--remote-debugging-port=9222",
                                   "--load-extension=/x", "--ignore-certificate-errors", "--user-data-dir=/tmp/x",
                                   "--allow-running-insecure-content", "--disable-site-isolation-trials", "--dns-over-https-mode=secure"])
def test_an_extra_argument_that_would_reopen_a_closed_channel_is_refused(extra):
    with pytest.raises(ValueError):
        build_launch_config("127.0.0.1", 18080, extra_args=[extra])


@pytest.mark.parametrize("extra", ["proxy", "-x", "--a b=c", 1, None])
def test_an_extra_argument_must_be_one_flag(extra):
    with pytest.raises(ValueError):
        build_launch_config("127.0.0.1", 18080, extra_args=[extra])


def test_a_harmless_extra_argument_is_appended_and_a_duplicate_is_not_repeated():
    cfg = build_launch_config("127.0.0.1", 18080, extra_args=["--font-render-hinting=none", "--disable-quic"])
    assert cfg.chromium_args[-1] == "--font-render-hinting=none" and list(cfg.chromium_args).count("--disable-quic") == 1


def test_every_forbidden_prefix_is_refused_in_both_spellings():
    for prefix in FORBIDDEN_PREFIXES:
        with pytest.raises(ValueError):
            build_launch_config("127.0.0.1", 18080, extra_args=[prefix])
        with pytest.raises(ValueError):
            build_launch_config("127.0.0.1", 18080, extra_args=[prefix + "=x"])


def test_the_profile_fields_are_what_an_adapter_profile_takes():
    cfg = build_launch_config("127.0.0.1", 18080)
    fields = cfg.profile_fields()
    assert fields["launch_args"] == tuple(cfg.chromium_args) and fields["proxy"] == {"server": "http://127.0.0.1:18080", "bypass": "<-loopback>"}


def test_the_policy_off_control_has_no_proxy_and_the_same_context_options():
    off = policy_off_config()
    assert off.chromium_args == () and off.playwright_proxy == {} and off.proxy_server == ""
    assert dict(off.context_options) == dict(CONTEXT_OPTIONS)


def test_the_configuration_is_deterministic():
    assert build_launch_config("127.0.0.1", 18080).golden_text() == build_launch_config("127.0.0.1", 18080).golden_text()


def test_the_adapter_package_accepts_these_fields_as_an_egress_profile():
    from agent_harness.qa.egress import EgressPolicy
    from qa_playwright import EgressProfile, ProxySettings
    fields = build_launch_config("127.0.0.1", 18080).profile_fields()
    profile = EgressProfile("p", EgressPolicy(entries=()), None, fields["launch_args"], ProxySettings(**fields["proxy"]))
    assert profile.proxy.bypass == "<-loopback>" and "--disable-quic" in profile.launch_args


def test_popups_and_downloads_are_denied_unless_the_specification_permits_them_and_nothing_else_loosens():
    base = build_launch_config("127.0.0.1", 18080)
    popups = build_launch_config("127.0.0.1", 18080, allow_popups=True)
    downloads = build_launch_config("127.0.0.1", 18080, allow_downloads=True)
    assert "--block-new-web-contents" in base.chromium_args and "--block-new-web-contents" not in popups.chromium_args
    assert list(popups.chromium_args) == [a for a in base.chromium_args if a != "--block-new-web-contents"]
    assert base.context_options["accept_downloads"] is False and downloads.context_options["accept_downloads"] is True
    assert dict(downloads.context_options, accept_downloads=False) == dict(base.context_options)
    assert downloads.chromium_args == base.chromium_args and popups.playwright_proxy == base.playwright_proxy
    assert any(a.startswith("--proxy-bypass-list=<-loopback>") for a in popups.chromium_args)
