# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The browser launch configuration that makes the egress gateway the only way out.

``build_launch_config`` returns the Chromium command-line flags, the Playwright proxy setting and the context options for a
browser that can reach the gateway and nothing else:

* **An explicit proxy for everything**, with ``--proxy-bypass-list=<-loopback>``. Chromium sends loopback destinations
  (``localhost``, ``127.0.0.0/8``, ``[::1]``) and link-local ones *directly* unless told otherwise (implicit bypass rules); a
  proxy that never sees them cannot enforce anything there. ``<-loopback>`` removes that implicit rule, so loopback, private
  and link-local destinations all go through the gateway and are decided by the policy. No other bypass entry is ever added.
* **No name resolution in the browser** (``--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE <gateway host>``): the browser cannot
  look anything up itself, so a path that skips the proxy has nothing to connect to.
* **Side channels closed**: QUIC (UDP, outside the proxy), WebRTC traffic that is not proxied, DNS prefetch and
  preconnect-style speculation, background networking, sync, update and telemetry-style components, extensions, new web
  contents (popups), permission prompts.
* **Context options**: downloads off, service workers blocked, no permissions, ``ignore_https_errors`` false, a fixed locale,
  timezone and viewport.

The proxy is given both as the launch flags and as Playwright's ``proxy`` option (``server`` and ``bypass``) so that a
Playwright-side default for per-context proxies cannot replace it; both carry the same value. Extra arguments are accepted
only if they cannot weaken any of this (``FORBIDDEN_PREFIXES``).

Which exact flag or Playwright option removes the implicit loopback bypass is a property of the pinned Chromium and Playwright
and is established by the browser-lane test (``tests/browser/test_eg_browser_loopback.py``), which also runs the control that
shows the bypass exists without it. That test was not run where this was written.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Sequence, Tuple

LOOPBACK_NOT_BYPASSED = "<-loopback>"

#: the fixed part of the flag set, in order. ``{server}`` and ``{host}`` are filled from the gateway address.
_FLAGS: Tuple[str, ...] = (
    "--proxy-server={server}",
    "--proxy-bypass-list=" + LOOPBACK_NOT_BYPASSED,
    "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE {host}",
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
)

#: arguments that would reopen what the fixed set closes
FORBIDDEN_PREFIXES: Tuple[str, ...] = (
    "--proxy-server", "--proxy-bypass-list", "--proxy-pac-url", "--proxy-auto-detect", "--no-proxy-server",
    "--host-resolver-rules", "--host-rules", "--enable-quic", "--origin-to-force-quic-on", "--webrtc-ip-handling-policy",
    "--force-webrtc-ip-handling-policy", "--enable-features", "--disable-web-security", "--remote-debugging",
    "--load-extension", "--enable-extensions", "--allow-running-insecure-content", "--ignore-certificate-errors",
    "--disable-features", "--user-data-dir", "--disable-site-isolation", "--allow-file-access", "--unsafely-treat-insecure-origin",
    "--auto-open-devtools", "--enable-automation", "--reduce-security", "--dns-over-https",
)

CONTEXT_OPTIONS: Dict[str, Any] = {
    "accept_downloads": False,
    "bypass_csp": False,
    "ignore_https_errors": False,
    "java_script_enabled": True,
    "locale": "en-US",
    "permissions": [],
    "service_workers": "block",
    "timezone_id": "UTC",
    "viewport": {"height": 720, "width": 1280},
}

_NAME = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")


@dataclass(frozen=True)
class LaunchConfig:
    proxy_server: str
    chromium_args: Tuple[str, ...]
    playwright_proxy: Mapping[str, str]
    context_options: Mapping[str, Any]

    def to_json(self) -> Dict[str, Any]:
        return {"chromium_args": list(self.chromium_args), "context_options": dict(self.context_options),
                "playwright_proxy": dict(self.playwright_proxy), "proxy_server": self.proxy_server}

    def golden_text(self) -> str:
        """The exact text the golden file holds (sorted keys, two-space indent, trailing newline)."""
        return json.dumps(self.to_json(), indent=2, sort_keys=True) + "\n"

    def profile_fields(self) -> Dict[str, Any]:
        """What an adapter egress profile takes: the launch arguments and the proxy (server and bypass)."""
        return {"launch_args": tuple(self.chromium_args), "proxy": {"server": self.proxy_server, "bypass": LOOPBACK_NOT_BYPASSED}}


def _host_text(host: str) -> str:
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        if _NAME.fullmatch(host) is None or len(host) > 253:
            raise ValueError("the gateway host must be an IP address or a plain lowercase DNS name")
        return host
    return f"[{parsed.compressed}]" if parsed.version == 6 else str(parsed)


def build_launch_config(gateway_host: str, gateway_port: int, *, extra_args: Sequence[str] = (), allow_popups: bool = False,
                        allow_downloads: bool = False) -> LaunchConfig:
    """The launch configuration for a browser whose only way out is the gateway at ``gateway_host:gateway_port``.

    Popups and downloads are denied unless the test specification permits them: ``allow_popups`` leaves out
    ``--block-new-web-contents`` and ``allow_downloads`` turns ``accept_downloads`` on. Nothing else can be loosened here."""
    if type(gateway_port) is not int or not 1 <= gateway_port <= 65535:
        raise ValueError("the gateway port must be between 1 and 65535")
    host = _host_text(gateway_host)
    server = f"http://{host}:{gateway_port}"
    exclude = host.strip("[]")
    args = [flag.format(server=server, host=exclude) for flag in _FLAGS if not (allow_popups and flag == "--block-new-web-contents")]
    for extra in extra_args:
        if type(extra) is not str or not extra.startswith("--") or " " in extra.split("=", 1)[0]:
            raise ValueError("an extra argument is a single --flag[=value]")
        if any(extra.split("=", 1)[0].startswith(p) for p in FORBIDDEN_PREFIXES):
            raise ValueError("this extra argument would weaken the egress controls")
        if extra in args:
            continue
        args.append(extra)
    options = dict(CONTEXT_OPTIONS)
    if allow_downloads:
        options["accept_downloads"] = True
    return LaunchConfig(proxy_server=server, chromium_args=tuple(args),
                        playwright_proxy={"server": server, "bypass": LOOPBACK_NOT_BYPASSED}, context_options=options)


def policy_off_config() -> LaunchConfig:
    """For the control test only: the same context options and no proxy at all, so Chromium's own defaults apply."""
    return LaunchConfig(proxy_server="", chromium_args=(), playwright_proxy={}, context_options=dict(CONTEXT_OPTIONS))
