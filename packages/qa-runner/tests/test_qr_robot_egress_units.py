# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Offline tests of the Robot lane's egress layers that need no kernel feature: the allow-list a plan gives them, the decision of the supervisor, the shape of the BPF program, the audit file's
format, the plan's profiles, the doctor check and the refusal before anything starts. What the layers DO to a process is shown by the experiments (``robot_egress/``), not here."""
import json
import struct

import pytest

from qa_runner import constants as K, egresslog, netfence
from qa_runner.egress import policy_config
from qa_runner.errors import PlanError

ORIGIN = "http://127.0.0.1:41234"


# ---- the policy and the decision ------------------------------------------------------------------------------------------------------
def test_the_allow_list_is_the_one_loopback_address_and_port_of_the_origin():
    allowed = netfence.allowed_endpoints(policy_config("origin-only", ORIGIN))
    assert [(str(n), p) for n, p in allowed] == [("127.0.0.1/32", 41234)]


@pytest.mark.parametrize("policy", [{}, {"private": []}, {"private": [{"networks": ["::1/128"], "ports": [80]}]}, {"private": [{"networks": ["127.0.0.1/32"], "ports": []}]},
                                    {"private": [{"networks": ["not-a-network"], "ports": [80]}]}, {"private": [{"networks": ["127.0.0.1/32"], "ports": [0, 70000, True, "80"]}]}, None])
def test_a_policy_that_names_no_ipv4_address_and_port_allows_nothing(policy):
    assert netfence.allowed_endpoints(policy) == []


@pytest.mark.parametrize("family,address,port,verdict,reason", [
    (2, "127.0.0.1", 41234, True, "in-allow-list"),
    (2, "127.0.0.1", 41235, False, "not-in-allow-list"),                      # another port
    (2, "127.0.0.2", 41234, False, "not-in-allow-list"),                      # the allowed port on another loopback address
    (2, "0.0.0.0", 41234, False, "not-in-allow-list"),                        # the alias of this host: not the address the policy names
    (2, "8.8.8.8", 41234, False, "not-in-allow-list"),
    (10, None, None, False, "address-family-not-permitted"),                  # IPv6
    (1, None, None, False, "address-family-not-permitted"),                   # a local socket
    (0, None, None, False, "address-family-not-permitted"),
    (2, None, 41234, False, "address-family-not-permitted"),
])
def test_the_decision_of_a_connect_is_deny_unless_the_address_and_port_are_the_allow_lists(family, address, port, verdict, reason):
    assert netfence.decide_connect(netfence.allowed_endpoints(policy_config("origin-only", ORIGIN)), family, address, port) == (verdict, reason)


def test_an_empty_allow_list_denies_everything():
    assert netfence.decide_connect([], 2, "127.0.0.1", 80) == (False, "not-in-allow-list")


# ---- the filter -----------------------------------------------------------------------------------------------------------------------
def _program(arch):
    raw = netfence.build_filter(arch)
    return [struct.unpack_from("<HBBI", raw, i) for i in range(0, len(raw), 8)]


@pytest.mark.parametrize("arch", list(netfence.ARCHES))
def test_the_filter_begins_by_refusing_any_other_architecture_and_every_jump_stays_inside_it(arch):
    prog = _program(arch)
    assert prog[0] == (netfence.BPF_LD_W_ABS, 0, 0, 4)                                            # load the architecture
    code, jt, jf, k = prog[1]
    assert (code, k) == (netfence.BPF_JEQ_K, netfence.ARCHES[arch]["audit"]) and prog[1 + 1 + jf][0] == netfence.BPF_RET_K and prog[2 + jf][3] == netfence.SECCOMP_RET_KILL_PROCESS
    for i, (code, jt, jf, k) in enumerate(prog):
        if code in (netfence.BPF_JEQ_K, netfence.BPF_JSET_K):
            assert i + 1 + jt < len(prog) and i + 1 + jf < len(prog)
    assert prog[-1][0] == netfence.BPF_RET_K and len(prog) < 120


def test_the_x86_64_filter_also_refuses_the_x32_call_numbers():
    prog = _program("x86_64")
    assert any(code == netfence.BPF_JSET_K and k == netfence.X32_SYSCALL_BIT for code, _, _, k in prog)
    assert not any(code == netfence.BPF_JSET_K and k == netfence.X32_SYSCALL_BIT for code, _, _, k in _program("aarch64"))


@pytest.mark.parametrize("arch", list(netfence.ARCHES))
def test_every_call_the_filter_decides_has_a_branch_and_the_default_is_allow(arch):
    prog = _program(arch)
    numbers = set(netfence.ARCHES[arch]["nr"].values())
    named = {k for code, _, _, k in prog if code == netfence.BPF_JEQ_K}
    assert numbers <= named
    first_ret = next(i for i, p in enumerate(prog) if p[0] == netfence.BPF_RET_K)
    assert prog[first_ret][3] == netfence.SECCOMP_RET_ALLOW                                       # a call the filter does not name is allowed


def test_the_kernel_structures_have_the_sizes_the_kernel_reports():
    import ctypes
    assert (ctypes.sizeof(netfence._Notif), ctypes.sizeof(netfence._Resp)) == (80, 24)


# ---- the audit file -------------------------------------------------------------------------------------------------------------------
HEADER = {"event": "mechanism", "layers": list(egresslog.ALL_LAYERS), "arch": "x86_64", "kernel": "6.8.0", "landlock_abi": 4, "allowed": ["127.0.0.1/32:41234"],
          "selftest": {"forbidden_tcp_refused": True, "udp_refused": True}}


def _file(*rows):
    return b"".join(json.dumps(r, sort_keys=True, separators=(",", ":")).encode() + b"\n" for r in rows)


def test_a_well_formed_log_parses_and_counts_refusals():
    rows = [HEADER, {"seq": 1, "layer": egresslog.LAYER_SECCOMP, "syscall": "connect", "verdict": "allow", "reason": "in-allow-list", "family": "AF_INET", "address": "127.0.0.1", "port": 41234},
            {"seq": 2, "layer": egresslog.LAYER_SECCOMP, "syscall": "socket", "verdict": "deny", "reason": "socket-kind-not-permitted", "family": "AF_INET", "detail": "SOCK_DGRAM/0"}]
    header, events, problems = egresslog.parse(_file(*rows))
    assert problems == [] and header["event"] == "mechanism" and len(events) == 2 and egresslog.denied(events) == 1


@pytest.mark.parametrize("name,data", [
    ("empty", b""),
    ("not json", b"nope\n"),
    ("a float", _file(HEADER).replace(b'"landlock_abi":4', b'"landlock_abi":4.5')[:-1] + b"\n"),
    ("a duplicate key", b'{"event":"mechanism","event":"mechanism"}\n'),
    ("unknown first line", _file({"event": "something"})),
    ("header with another key", _file({**HEADER, "extra": 1})),
    ("sequence gap", _file(HEADER, {"seq": 2, "syscall": "connect", "verdict": "allow", "reason": "x"})),
    ("unknown verdict", _file(HEADER, {"seq": 1, "syscall": "connect", "verdict": "maybe", "reason": "x"})),
    ("unknown field", _file(HEADER, {"seq": 1, "syscall": "connect", "verdict": "allow", "reason": "x", "pid": 4})),
    ("port not a port", _file(HEADER, {"seq": 1, "syscall": "connect", "verdict": "allow", "reason": "x", "port": 70000})),
    ("unavailable with decisions", _file({"event": "unavailable", "reason": "x", "message": "m", "facts": {}}, {"seq": 1, "syscall": "connect", "verdict": "allow", "reason": "x"})),
    ("not utf-8", b"\xff\xfe\n"),
])
def test_a_malformed_log_is_reported_never_repaired(name, data):
    assert egresslog.parse(data)[2], name


# ---- plans and wording ----------------------------------------------------------------------------------------------------------------
def test_a_robot_lane_may_ask_for_the_layers_or_for_nothing_and_nothing_else(up):
    from qa_runner.golden import robot_plan
    from qa_runner.plan import freeze_plan
    for profile in ("origin-only", "not-enforced"):
        assert freeze_plan(up, robot_plan(profile)).lane("robot").egress == profile
    with pytest.raises(PlanError) as exc:
        freeze_plan(up, robot_plan("gateway"))
    assert exc.value.code == "BAD_EGRESS_PROFILE"


def test_the_two_profiles_give_two_different_plan_digests(up):
    from qa_runner.golden import robot_plan
    from qa_runner.plan import freeze_plan
    assert freeze_plan(up, robot_plan("origin-only")).plan_digest != freeze_plan(up, robot_plan("not-enforced")).plan_digest


def test_the_statement_of_the_layers_does_not_claim_more_than_the_experiments_show():
    text = K.robot_egress_layers_text(["robot"])
    for must in ("What this does not stop", "second thread", "CAP_SYS_PTRACE", "guard, not a sandbox", "does not start if they cannot be installed", "egress-denied", "not by the egress gateway"):
        assert must in text, must
    for must_not in ("sandbox is", "secure", "tamper", "all traffic", "NOT enforced"):
        assert must_not not in text, must_not


def test_extra_limitations_follow_each_lanes_profile(up):
    from qa_runner.bundle import extra_limitations
    from qa_runner.golden import golden_plan, robot_plan
    from qa_runner.plan import freeze_plan
    ids = lambda plan: [x["id"] for x in extra_limitations(freeze_plan(up, plan))]
    assert ids(robot_plan("origin-only")) == [K.ROBOT_EGRESS_LAYERS_ID]
    assert ids(robot_plan("not-enforced")) == [K.ROBOT_EGRESS_LIMITATION_ID]
    assert ids(golden_plan()) == []
    from types import SimpleNamespace as L
    lanes = L(lanes=(L(lane_id="robot", engine=K.ENGINE_ROBOT, egress="origin-only"), L(lane_id="robot2", engine=K.ENGINE_ROBOT, egress="not-enforced"), L(lane_id="browser", engine=K.ENGINE_PLAYWRIGHT, egress="origin-only")))
    # a plan with two Robot lanes of different profiles gets both statements, each naming only its own lane (the browser lane gets none)
    limits = {x["id"]: x["text"] for x in extra_limitations(lanes)}
    assert limits[K.ROBOT_EGRESS_LAYERS_ID] == K.robot_egress_layers_text(["robot"]) and limits[K.ROBOT_EGRESS_LIMITATION_ID] == K.robot_egress_limitation_text(["robot2"]) and len(limits) == 2


# ---- the doctor check and the refusal before anything starts --------------------------------------------------------------------------
GOOD = {"ok": True, "facts": {"landlock_abi": 4, "kernel": "6.8.0", "machine": "x86_64"}, "checks": {"allowed_connect_works": True, "other_port_refused": True, "udp_refused": True, "ipv6_refused": True}}
BAD = {"ok": False, "reason": "landlock-network-rules-unavailable", "message": "Landlock network rules need ABI 4 or later", "facts": {"landlock_abi": 0}}


def test_doctor_reports_the_layers_available_when_the_probe_measured_them():
    from qa_runner.doctor import check_robot_egress
    c = check_robot_egress(lambda: GOOD)
    assert c.status == "OK" and "Landlock (ABI 4)" in c.detail and "measurement of this host" in c.detail


def test_doctor_fails_clearly_when_the_plan_needs_the_layers_and_they_are_unavailable():
    from qa_runner.doctor import check_robot_egress
    c = check_robot_egress(lambda: BAD)
    assert c.status == "FAIL" and "landlock-network-rules-unavailable" in c.detail and "does not start" in c.detail and "no weaker mode" in c.detail and "not-enforced" in c.remedy


def test_doctor_does_not_fail_for_a_plan_that_does_not_need_the_layers():
    from qa_runner.doctor import check_robot_egress
    called = []
    c = check_robot_egress(lambda: called.append(1) or BAD, needed=False)
    assert c.status == "OK" and not called and "not needed" in c.detail


def test_a_failed_probe_is_a_fail_not_a_pass():
    from qa_runner.doctor import check_robot_egress
    assert check_robot_egress(lambda: {"ok": False, "reason": "probe-failed", "message": "x"}).status == "FAIL"
    assert check_robot_egress(lambda: {"reason": "something"}).status == "FAIL"                      # no 'ok' at all
    assert check_robot_egress(lambda: {"ok": "yes"}).status == "FAIL"                                # only True is a pass


def test_run_doctor_has_the_check_for_a_plan_with_a_robot_lane_and_only_then(monkeypatch):
    from qa_runner import doctor
    seen = []
    monkeypatch.setattr(doctor, "check_robot_egress", lambda needed=True: seen.append(needed) or doctor.Check("robot egress layers", "OK", ""))
    for name in ("check_python", "check_platform", "check_workdir", "check_first_party_modules", "check_pins", "check_pinned_files", "check_playwright", "check_robot", "check_fixture_app",
                 "check_egress_gateway", "check_path_policy"):
        monkeypatch.setattr(doctor, name, lambda *a, _n=name, **k: doctor.Check(_n, "OK", ""))
    assert "robot egress layers" in [c.name for c in doctor.run_doctor((K.ENGINE_PLAYWRIGHT, K.ENGINE_ROBOT), robot_egress=False)] and seen == [False]
    assert "robot egress layers" not in [c.name for c in doctor.run_doctor((K.ENGINE_PLAYWRIGHT,))]
