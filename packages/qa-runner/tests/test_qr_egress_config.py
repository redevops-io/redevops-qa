# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The egress protections as configuration, offline (no browser): what doctor and the browser lane accept as a launch configuration, and that both fail closed when the gateway or the
launch configuration is not available. That Chromium obeys the configuration is shown by the egress lane (``tests/egress``), which needs a real browser."""
import json

import pytest

import qa_egress
import qa_runner.doctor as doctor
from qa_egress import build_launch_config, policy_off_config
from qa_runner.egress import launch_config_problems
from qa_runner.golden import golden_plan
from qa_runner.lane_browser import GatewayLost, LaunchConfigRefused, gateway_snapshot, run_lane
from qa_runner.orchestrate import lane_input
from qa_runner.plan import freeze_plan

PORT = 40123


def fields(**kw):
    return build_launch_config("127.0.0.1", PORT, **kw).profile_fields()


def test_the_launch_configuration_of_the_package_has_no_problem():
    assert launch_config_problems(fields(), PORT) == []
    assert launch_config_problems(fields(allow_popups=True, allow_downloads=True), PORT) == []


def test_a_launch_configuration_for_another_port_is_refused():
    assert launch_config_problems(fields(), PORT + 1)


def test_a_browser_with_no_proxy_is_not_a_launch_configuration():
    assert len(launch_config_problems(policy_off_config().profile_fields(), PORT)) >= 5


EDITS = [
    ("proxy flag removed", lambda f: f.update(launch_args=tuple(a for a in f["launch_args"] if not a.startswith("--proxy-server")))),
    ("loopback bypass flag removed", lambda f: f.update(launch_args=tuple(a for a in f["launch_args"] if not a.startswith("--proxy-bypass-list")))),
    ("loopback bypass flag changed", lambda f: f.update(launch_args=tuple("--proxy-bypass-list=localhost" if a.startswith("--proxy-bypass-list") else a for a in f["launch_args"]))),
    ("a second bypass list", lambda f: f.update(launch_args=f["launch_args"] + ("--proxy-bypass-list=*",))),
    ("name resolution allowed", lambda f: f.update(launch_args=tuple(a for a in f["launch_args"] if not a.startswith("--host-resolver-rules")))),
    ("quic allowed", lambda f: f.update(launch_args=tuple(a for a in f["launch_args"] if a != "--disable-quic"))),
    ("webrtc udp allowed", lambda f: f.update(launch_args=tuple(a for a in f["launch_args"] if not a.startswith("--force-webrtc-ip-handling-policy")))),
    ("no proxy server flag added", lambda f: f.update(launch_args=f["launch_args"] + ("--no-proxy-server",))),
    ("a pac url added", lambda f: f.update(launch_args=f["launch_args"] + ("--proxy-pac-url=http://127.0.0.1:1/x",))),
    ("playwright proxy bypass changed", lambda f: f.update(proxy={**f["proxy"], "bypass": "localhost"})),
    ("playwright proxy names another server", lambda f: f.update(proxy={**f["proxy"], "server": "http://127.0.0.1:1"})),
    # a later switch overrides an earlier one: presence is not enough
    ("a later webrtc policy overrides the first", lambda f: f.update(launch_args=f["launch_args"] + ("--force-webrtc-ip-handling-policy=default",))),
    ("a later host resolver rule gives the browser names back", lambda f: f.update(launch_args=f["launch_args"] + ("--host-resolver-rules=MAP * 127.0.0.1",))),
    ("features switched on again", lambda f: f.update(launch_args=f["launch_args"] + ("--disable-features=NetworkService",))),
    ("a proxy bypass rule", lambda f: f.update(launch_args=f["launch_args"] + ("--proxy-bypass-rules=*",))),
    ("a remote debugging port", lambda f: f.update(launch_args=f["launch_args"] + ("--remote-debugging-port=9222",))),
    ("a switch given twice with the same value", lambda f: f.update(launch_args=f["launch_args"] + ("--disable-quic",))),
]


@pytest.mark.parametrize("name,edit", EDITS, ids=[n for n, _ in EDITS])
def test_every_protection_removed_from_the_launch_configuration_is_named(name, edit):
    f = fields()
    f = {"launch_args": tuple(f["launch_args"]), "proxy": dict(f["proxy"])}
    edit(f)
    assert launch_config_problems(f, PORT), name


# ---- doctor fails closed --------------------------------------------------------------------------------------------------------------------
def test_doctor_passes_the_egress_check_with_the_real_gateway_and_launch_configuration():
    c = doctor.check_egress_gateway()
    assert c.status == "OK" and "Robot lane" in c.detail and "not by this check" in c.detail


def test_doctor_fails_when_the_launch_configuration_is_unavailable(monkeypatch):
    def broken(*a, **k):
        raise RuntimeError("no launch configuration")
    monkeypatch.setattr(qa_egress, "build_launch_config", broken)
    c = doctor.check_egress_gateway()
    assert c.status == "FAIL" and "launch configuration is unavailable" in c.detail and "refuses to continue" in c.detail
    assert [x.name for x in doctor.run_doctor(include=[doctor.check_egress_gateway]) if x.status == "FAIL"] == ["egress gateway"]


def test_doctor_fails_when_the_launch_configuration_does_not_force_loopback_through_the_gateway(monkeypatch):
    real = qa_egress.build_launch_config

    def weak(host, port, **kw):
        cfg = real(host, port, **kw)

        class Weak:
            chromium_args = tuple(a for a in cfg.chromium_args if not a.startswith("--proxy-bypass-list"))

            def profile_fields(self):
                return {"launch_args": self.chromium_args, "proxy": {"server": cfg.proxy_server, "bypass": ""}}
        return Weak()
    monkeypatch.setattr(qa_egress, "build_launch_config", weak)
    c = doctor.check_egress_gateway()
    assert c.status == "FAIL" and "only way out" in c.detail and "loopback" in c.detail


def test_doctor_fails_when_the_gateway_cannot_start_and_the_exit_status_says_so(monkeypatch):
    class Broken:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            raise OSError("cannot bind")

        def __exit__(self, *a):
            pass
    monkeypatch.setattr(qa_egress, "GatewayServer", Broken)
    c = doctor.check_egress_gateway()
    assert c.status == "FAIL" and "refuses to continue" in c.detail
    text = doctor.render([c])
    assert "[FAIL] egress gateway" in text and "a run would not be what it says" in text


# ---- the lane fails closed ------------------------------------------------------------------------------------------------------------------
@pytest.fixture()
def cfg(up, tmp_path):
    fl = freeze_plan(up, golden_plan()).lane("browser")
    return lane_input(fl, run_id="r0-egress", origin="http://127.0.0.1:9", out_dir=str(tmp_path / "out"))


def test_the_lane_refuses_to_start_a_browser_when_the_launch_configuration_is_unavailable(monkeypatch, cfg):
    def broken(*a, **k):
        raise RuntimeError("no launch configuration")
    monkeypatch.setattr(qa_egress, "build_launch_config", broken)
    with pytest.raises(RuntimeError, match="no launch configuration"):
        run_lane(cfg)


def test_the_lane_refuses_to_start_a_browser_with_a_launch_configuration_that_lets_loopback_go_direct(monkeypatch, cfg):
    real = qa_egress.build_launch_config

    def weak(host, port, **kw):
        c = real(host, port, **kw)

        class Weak:
            def profile_fields(self):
                f = c.profile_fields()
                return {"launch_args": tuple(a for a in f["launch_args"] if not a.startswith("--proxy-bypass-list")), "proxy": f["proxy"]}
        return Weak()
    monkeypatch.setattr(qa_egress, "build_launch_config", weak)
    with pytest.raises(LaunchConfigRefused, match="only way out"):
        run_lane(cfg)


def test_a_lane_whose_launch_configuration_is_refused_writes_an_error_result_and_exits_non_zero(monkeypatch, cfg, tmp_path):
    from qa_runner import lane_browser
    monkeypatch.setattr(qa_egress, "build_launch_config", lambda host, port, **kw: type("W", (), {"profile_fields": lambda self: {"launch_args": (), "proxy": {}}})())
    inp = tmp_path / "input.json"
    from qa_evidence.canon import dumps_canonical
    inp.write_bytes(dumps_canonical({k: v for k, v in cfg.items() if k != "parent_pid"}))          # with a parent pid the lane starts a watchdog that ends the process group of a parent that is not its own
    assert lane_browser.main([str(inp)]) == 3
    doc = json.loads((tmp_path / "out" / "lane-result.json").read_text())
    assert doc["status"] == "ERROR" and doc["error_class"] == "LaunchConfigRefused" and "outcome" not in doc


def test_the_error_classes_are_distinct_and_are_runtime_errors():
    assert issubclass(GatewayLost, RuntimeError) and issubclass(LaunchConfigRefused, RuntimeError) and GatewayLost is not LaunchConfigRefused


# ---- a gateway that is lost before the lane ends ----------------------------------------------------------------------------------------------
def _gateway(up):
    from qa_egress import GatewayServer
    from qa_egress.resolver import SystemResolver
    policy = up.harness.egress.EgressPolicy.from_config({"private": [{"host": "127.0.0.1", "networks": ["127.0.0.1/32"], "schemes": ["http"], "ports": [1], "label": "t"}]})
    return GatewayServer(policy, SystemResolver())


def test_a_running_gateway_gives_its_decisions(up):
    with _gateway(up) as gw:
        assert gateway_snapshot(gw) == []


def test_a_gateway_that_was_stopped_is_a_lost_gateway_not_an_empty_log(up):
    gw = _gateway(up).start()
    gw.stop()
    with pytest.raises(GatewayLost, match="lost before the lane ended"):
        gateway_snapshot(gw)


def test_a_gateway_that_does_not_answer_is_a_lost_gateway(up):
    class Silent:
        running = True

        def wait_idle(self):
            raise TimeoutError("connections still in flight")

        def events(self):
            return []
    with pytest.raises(GatewayLost):
        gateway_snapshot(Silent())
