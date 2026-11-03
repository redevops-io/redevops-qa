# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Egress profiles as data. A lane names a profile; the profile turns the origin of the target into an allow-list in the form the harness
``EgressPolicy.from_config`` reads. The data is recorded in the bundle (``lanes/<lane>/egress-profile.json``), so what a lane was allowed to reach is part
of the evidence. Later hardening adds profiles here without changing the lanes."""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Mapping

from .errors import PlanError


def policy_config(profile: str, origin: str) -> Dict[str, Any]:
    """The allow-list of the ``origin-only`` profile for the origin of a target: one loopback address, one port, plain http. The browser lane gives it to the gateway; the Robot lane
    gives it to the kernel layers (``netfence``), which read the address and the port from it."""
    if profile != "origin-only":
        raise PlanError("BAD_EGRESS_PROFILE", f"unknown egress profile {profile!r}")
    parts = urllib.parse.urlsplit(origin)
    if parts.scheme != "http" or parts.hostname not in ("127.0.0.1",) or parts.port is None:
        raise PlanError("BAD_ORIGIN", "the origin-only profile allows exactly one http loopback origin (127.0.0.1 and an explicit port)")
    return {"private": [{"host": parts.hostname, "networks": [f"{parts.hostname}/32"], "schemes": ["http"], "ports": [parts.port], "label": "target-origin"}]}


def launch_config_problems(fields: Mapping[str, Any], gateway_port: int) -> List[str]:
    """What is wrong with a browser launch configuration (``LaunchConfig.profile_fields()``) as a way to make the gateway at ``127.0.0.1:gateway_port`` the browser's only way out.
    An empty list means every protection this release relies on is present and nothing else is added (the arguments are exactly a subset of those ``qa_egress.launch`` produces, none twice): the explicit proxy, the removal of Chromium's implicit loopback bypass (both as a flag and as the Playwright
    proxy option), no name resolution in the browser, no QUIC, no WebRTC traffic outside the proxy. It does NOT show that the browser obeys them; the egress tests do, against a hostile page.
    Doctor and the browser lane both call this, so a lane never starts a browser with a weaker configuration than the one doctor accepted."""
    problems: List[str] = []
    args = list(fields.get("launch_args") or ())
    proxy = dict(fields.get("proxy") or {})
    server = f"http://127.0.0.1:{gateway_port}"
    if proxy.get("server") != server:
        problems.append("the Playwright proxy does not name the gateway")
    if proxy.get("bypass") != "<-loopback>":
        problems.append("the Playwright proxy option does not remove the implicit loopback bypass")
    for need, why in ((f"--proxy-server={server}", "the browser is not told to use the gateway as its proxy"),
                      ("--proxy-bypass-list=<-loopback>", "loopback is not forced through the proxy (Chromium would send it direct)"),
                      ("--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1", "the browser can resolve names itself"),
                      ("--disable-quic", "QUIC (UDP outside the proxy) is not disabled"),
                      ("--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "WebRTC may send UDP outside the proxy")):
        if need not in args:
            problems.append(why)
    if any(a.startswith(("--no-proxy-server", "--proxy-pac-url", "--proxy-auto-detect", "--enable-quic")) for a in args):
        problems.append("an argument reopens a way around the proxy")
    if len([a for a in args if a.startswith("--proxy-bypass-list")]) != 1 or len([a for a in args if a.startswith("--proxy-server")]) != 1:
        problems.append("the proxy flags are repeated")
    # A CLOSED set: Chromium takes the last occurrence of a switch, so an argument that the launch configuration does not itself produce (or a repeated switch) can undo any of the above
    # (``--force-webrtc-ip-handling-policy=default``, ``--host-resolver-rules=...``, ``--disable-features=...``, ``--proxy-bypass-rules=...``, ``--remote-debugging-port``).
    from qa_egress import launch as _launch                   # the module's own function, whatever a test or a caller did to the package-level name
    allowed = set(_launch.build_launch_config("127.0.0.1", gateway_port).chromium_args)
    for a in args:
        if a not in allowed:
            problems.append("an argument the launch configuration does not produce: " + str(a).split("=", 1)[0][:60])
    names = [str(a).split("=", 1)[0] for a in args]
    for name in sorted({n for n in names if names.count(n) > 1}):
        problems.append("a switch is given more than once: " + name[:60])
    return problems
