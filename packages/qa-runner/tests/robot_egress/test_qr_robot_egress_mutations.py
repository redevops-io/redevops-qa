# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Mutation tests of the Robot lane's egress layers: each removes or weakens ONE protection in a copy of the source and requires the experiment that is about it to go red. A layer is only worth
having if disabling it makes the matching experiment fail; the same experiments must pass on the unmodified copy. Linux, Robot Framework installed (the experiments run the real lane child)."""
import re

import pytest

from qr_mutation import baseline_result, mutant_result

EXP = "robot_egress/test_qr_robot_egress_experiments.py"
RUN = "robot_egress/test_qr_robot_egress_run.py"


def x(name):
    return f"{EXP}::{name}"


def r(name):
    return f"{RUN}::{name}"


MATRIX = "test_what_each_configuration_reaches_and_blocks"
AUDIT = "test_every_refused_attempt_is_in_the_audit_record"
TAMPER = "test_every_edit_that_hides_a_refusal_or_overstates_the_layers_is_rejected_with_the_finding_that_names_it"

CASES = [
    # ---- the seccomp layer ----------------------------------------------------------------------------------------------------------
    ("the supervisor lets every connect through", "netfence.py", '    return (True, "in-allow-list") if any(ip in net and port == p for net, p in allowed) else (False, "not-in-allow-list")',
     '    return True, "in-allow-list"', [x(f"{MATRIX}[seccomp-only-direct]")]),
    ("the supervisor looks at the port only, not the address", "netfence.py", "ip in net and port == p for net, p in allowed", "port == p for net, p in allowed", [x(f"{MATRIX}[both-same_port_other_ip]")]),
    ("the supervisor looks at the address only, not the port", "netfence.py", "ip in net and port == p for net, p in allowed", "ip in net for net, p in allowed", [x(f"{MATRIX}[seccomp-only-direct]")]),
    ("an internet socket of any type is allowed", "netfence.py", '    a.label("sock_inet")\n    a.ld(_ARG_LO(1))\n    a.alu_and(SOCK_TYPE_MASK)\n    a.jeq(SOCK_STREAM, None, "notify")',
     '    a.label("sock_inet")\n    a.ld(_ARG_LO(1))\n    a.alu_and(SOCK_TYPE_MASK)\n    a.jeq(SOCK_STREAM, None, None)', [x(f"{MATRIX}[seccomp-only-udp]")]),
    ("a family other than IPv4 and local is allowed", "netfence.py", 'a.jeq(AF_INET, "sock_inet", "notify")', 'a.jeq(AF_INET, "sock_inet", "allow")', [x(f"{MATRIX}[seccomp-only-udp6]")]),
    ("a connect to a local socket path is allowed", "netfence.py", 'return False, {"syscall": "connect", "family": "AF_UNIX"', 'return True, {"syscall": "connect", "family": "AF_UNIX"',
     [x(f"{MATRIX}[seccomp-only-unix_stream]")]),
    ("TCP Fast Open through sendmsg is allowed", "netfence.py", '    a.label("g_sendmsg")\n    a.ld(_ARG_LO(2))\n    a.jset(MSG_FASTOPEN, "notify", "allow")',
     '    a.label("g_sendmsg")\n    a.ld(_ARG_LO(2))\n    a.jset(MSG_FASTOPEN, "allow", "allow")', [x(f"{MATRIX}[seccomp-only-fast_open_sendmsg]")]),
    ("a datagram socketpair is allowed", "netfence.py", '    a.jeq(SOCK_STREAM, "allow", "notify")\n    # sendto', '    a.jeq(SOCK_STREAM, "allow", "allow")\n    # sendto', [x(f"{MATRIX}[seccomp-only-unix_dgram_pair]")]),
    ("the seccomp filter is not installed", "netfence.py", "            fence._fd = _install_seccomp(libc, arch)\n            fence._ready.set()", "            fence._fd = None",
     [x(f"{MATRIX}[seccomp-only-udp]"), x("test_the_log_says_which_layers_were_installed_and_the_self_test_that_passed[seccomp-only-layers1]")]),
    ("the supervisor answers every call with continue", "netfence.py", "error=0 if allow else -errno.EACCES, flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE if allow else 0", "error=0, flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE",
     [x(f"{MATRIX}[seccomp-only-direct]")]),
    ("the supervisor records nothing", "netfence.py", '        self._record(verdict="allow" if allow else "deny", **fields)\n', "", [x(f"{AUDIT}[direct-both]"), x("test_the_allowed_origin_is_allowed_and_recorded_as_such[both]")]),
    # ---- the Landlock layer ---------------------------------------------------------------------------------------------------------
    ("the Landlock layer is not installed", "netfence.py", "            _install_landlock(libc, [port for _, port in allowed])", "            pass", [x(f"{MATRIX}[landlock-only-direct]"), x(f"{MATRIX}[landlock-only-ip_literal_http]")]),
    ("Landlock allows every port", "netfence.py", "        for port in sorted(set(ports)):\n", "        for port in range(1, 65536):\n", [x(f"{MATRIX}[landlock-only-direct]")]),
    # ---- the lane ----------------------------------------------------------------------------------------------------------------------
    ("the lane starts the engine without installing the layers", "lane_robot.py", "                fence = netfence.install(policy, layers=layers)", "                fence = None",
     [x(f"{MATRIX}[both-direct]"), x("test_a_refused_attempt_ends_the_lane_as_an_engine_error_not_a_pass")]),
    ("a refusal does not change the lane's status", "lane_robot.py", '        if status in ("NATIVE_PASS", "NATIVE_FAIL", "NATIVE_SKIPPED") and (fence.lost or fence.denied):', "        if False:",
     [x("test_a_refused_attempt_ends_the_lane_as_an_engine_error_not_a_pass"), r("test_a_refused_attempt_ends_the_lane_as_an_engine_error_with_no_verdict_and_the_listener_saw_nothing")]),
    # ---- verify ------------------------------------------------------------------------------------------------------------------------
    ("verify accepts a refusal in the log of a lane reported as completed", "verify.py", '        if refused and native["status"] in ("NATIVE_PASS", "NATIVE_FAIL"):', "        if False:",
     [r(f"{TAMPER}[the lane relabelled as a completed pass, everything recomputed]")]),
    ("verify accepts egress-denied without a refusal in the log", "verify.py", '        if native["raw_status"] in EGRESS_RAW and (native["status"] != "NATIVE_ERROR" or not refused):', "        if False:",
     [r(f"{TAMPER}[the refusals removed from the log, the lane still says egress-denied]")]),
    ("verify accepts egress-denied without a log", "verify.py", '            if native["raw_status"] in EGRESS_RAW:\n                v.add("EGRESS_DENIAL_NOT_IN_LOG"', '            if False:\n                v.add("EGRESS_DENIAL_NOT_IN_LOG"',
     [r(f"{TAMPER}[the log removed from the bundle, the lane still says egress-denied]")]),
    ("verify does not check the layers and the allow-list the log names", "verify.py", 'if header.get("layers") != list(egresslog.ALL_LAYERS) or header.get("allowed") != allowed or', 'if False and header.get("layers") != list(egresslog.ALL_LAYERS) or header.get("allowed") != allowed or',
     [r(f"{TAMPER}[the log claims only one layer was installed]")]),
    ("verify does not look at allowed decisions", "verify.py", '            if e["verdict"] == "allow" and not (', '            if False and e["verdict"] == "allow" and not (',
     [r(f"{TAMPER}[an allowed connect to an address outside the allow-list added to the log]")]),
    ("verify does not read the log's problems", "verify.py", '        if problems:\n            v.add("EGRESS_LOG_MALFORMED", path, safe_text("; ".join(problems[:3]), 200))', '        if False:\n            v.add("EGRESS_LOG_MALFORMED", path, safe_text("; ".join(problems[:3]), 200))',
     [r(f"{TAMPER}[a record of the log that is not a decision]")]),
    ("verify does not compare the report's count of refusals with the logs", "verify.py", "    if reported is not None and (not ran or reported != total):", "    if False:",
     [r("test_the_extension_count_cannot_be_changed_and_the_statement_cannot_be_swapped_for_the_old_one")]),
    ("verify does not accept the lower status of a refused lane", "verify.py", 'got[0] == "NATIVE_ERROR" and got[1] in EGRESS_RAW and _egress_refused(files, lid):', "False:",
     [r("test_the_verifier_accepts_the_honest_bundle_of_a_refused_lane_and_it_is_never_verified")]),
]


@pytest.mark.parametrize("name,rel,old,new,tests", CASES, ids=[c[0] for c in CASES])
def test_disabling_a_protection_makes_the_matching_experiment_fail(tmp_path, name, rel, old, new, tests):
    result = mutant_result(tmp_path, rel, old, new, tests)
    assert result.returncode == 1, f"mutant not killed by a failing test (exit {result.returncode}): {name}\n{result.stdout[-2500:]}"
    assert re.search(r"\b[1-9][0-9]* failed\b", result.stdout), result.stdout[-1500:]


def test_the_selected_experiments_pass_on_an_unmodified_copy(tmp_path):
    tests = sorted({t for c in CASES for t in c[4]})
    result = baseline_result(tmp_path, tests)
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-1500:]
