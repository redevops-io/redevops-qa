# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The Robot lane's egress layers in a whole run: the real orchestrator, the real fixture app, the real Robot Framework and a reviewed library that, besides asking the app for the order totals,
tries to reach a hostile loopback listener the plan's allow-list does not name. A refused attempt must end the lane as an engine error with the attempt in the bundle's audit file, never as a pass
or a verdict; the verifier accepts the honest bundle and rejects every edit that hides the refusal or claims more than the evidence shows."""
import json
import shutil
import socket
import threading
from dataclasses import replace

import pytest

from qa_runner import constants as K, egresslog, suites
from qa_runner.golden import robot_plan
from qa_runner.orchestrate import RunOptions, run_plan
from qa_runner.plan import freeze_plan

from qr_tamper import codes, edit_json, forge_consistently, put, rechain, verify_files_in


class Listener:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.1)
        self.hits = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.sock.getsockname()[1]

    def loop(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
                self.hits += 1
                conn.close()
            except (socket.timeout, OSError):
                continue

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.sock.close()


def hostile_copy(tmp_path, monkeypatch, port):
    """The reviewed suite with ONE change: after asking the app for an order, its library tries to reach a hostile loopback port (and swallows the error, so Robot itself reports PASS)."""
    copy = tmp_path / "suite"
    shutil.copytree(suites.SUITE_DIR, copy)
    api = (copy / "OrderApi.py").read_text()
    anchor = '    total = body.get("total_cents")\n'
    assert anchor in api
    attempt = f"    try:\n        import socket\n        socket.create_connection(('127.0.0.1', {port}), timeout=2).close()\n    except OSError:\n        pass\n"
    (copy / "OrderApi.py").write_text(api.replace(anchor, attempt + anchor))
    monkeypatch.setattr(suites, "SUITE_DIR", copy)


@pytest.fixture(scope="module")
def clean(up):
    frozen = freeze_plan(up, robot_plan())
    return frozen, run_plan(up, frozen, RunOptions(defect="none", run_id="r0-clean", lane_deadline_s=120))


@pytest.fixture(scope="module")
def hostile(up, tmp_path_factory):
    """One whole run with the hostile library (module scoped: the cases below read the same bundle)."""
    tmp = tmp_path_factory.mktemp("hostile")
    listener = Listener()
    mp = pytest.MonkeyPatch()
    try:
        hostile_copy(tmp, mp, listener.port)
        frozen = freeze_plan(up, robot_plan())
        summary = run_plan(up, frozen, RunOptions(defect="none", run_id="r0-hostile", lane_deadline_s=120))
        yield frozen, summary, listener
    finally:
        mp.undo()
        listener.close()


def report(s):
    return json.loads(s.bundle.files["report.json"])


# ---- the clean run ---------------------------------------------------------------------------------------------------------------------
def test_a_clean_run_is_verified_with_both_layers_installed_and_nothing_refused(clean, tmp_path):
    frozen, s = clean
    assert (s.outcome, s.exit_code, s.lanes) == ("VERIFIED", 0, (("robot", "NATIVE_PASS"),))
    header, events, problems = egresslog.parse(s.bundle.files["lanes/robot/egress-log.jsonl"])
    assert not problems and header["layers"] == list(egresslog.ALL_LAYERS) and egresslog.denied(events) == 0
    assert [(e["syscall"], e["verdict"], e["address"]) for e in events] == [("connect", "allow", "127.0.0.1")] * 4          # the library's four order requests, and nothing else
    assert report(s)["extensions"]["egress_fence_denied"] == 0
    v = verify_files_in(tmp_path, s.bundle.files, plan_digest=frozen.plan_digest)
    assert v.accepted and not v.findings, [f.to_json() for f in v.findings]


# ---- a refused attempt ---------------------------------------------------------------------------------------------------------------
def test_a_refused_attempt_ends_the_lane_as_an_engine_error_with_no_verdict_and_the_listener_saw_nothing(hostile):
    frozen, s, listener = hostile
    r = report(s)
    assert s.lanes == (("robot", "NATIVE_ERROR"),) and r["lanes"][0]["native"]["raw_status"] == "egress-denied"
    assert s.outcome == "INCONCLUSIVE" and s.exit_code == K.EXIT_ENVIRONMENT and r["accounting"]["verified"] == 0
    assert r["accounting"]["results"][0]["verdict"]["reason_code"] == "EVIDENCE_MISSING"
    assert listener.hits == 0, "the hostile listener was reached: the layers did not hold"
    assert r["extensions"]["egress_fence_denied"] == 4                                      # one refused connect after each of the four order requests


def test_the_refusals_are_in_the_bundles_audit_file_with_the_address_and_port(hostile):
    frozen, s, listener = hostile
    header, events, problems = egresslog.parse(s.bundle.files["lanes/robot/egress-log.jsonl"])
    assert not problems
    denied = [e for e in events if e["verdict"] == "deny"]
    assert len(denied) == 4 and all((e["syscall"], e["address"], e["port"], e["reason"]) == ("connect", "127.0.0.1", listener.port, "not-in-allow-list") for e in denied)
    assert len([e for e in events if e["verdict"] == "allow"]) == 4


def test_the_native_files_of_the_refused_lane_are_kept_and_say_pass_while_the_report_does_not(hostile):
    """The engine's own report says PASS (the library swallowed the error): the lane's status is lower than the engine's, on purpose, and the verifier accepts exactly that direction."""
    frozen, s, _ = hostile
    assert json.loads(s.bundle.files["lanes/robot/native/adapter-result.json"])["status"] == "PASS" and "lanes/robot/observations.json" not in s.bundle.files


def test_the_report_and_the_text_summary_say_what_the_layers_refused(hostile, tmp_path):
    from qa_evidence.inspector import inspect_bundle
    from qa_evidence.render import render_text
    frozen, s, _ = hostile
    assert K.ROBOT_EGRESS_LAYERS_ID in [x["id"] for x in report(s)["limitations"]]
    target = tmp_path / "bundle"
    s.bundle.write_directory(str(target))
    assert "egress-denied" in render_text(inspect_bundle(str(target)))


def test_the_verifier_accepts_the_honest_bundle_of_a_refused_lane_and_it_is_never_verified(hostile, tmp_path):
    frozen, s, _ = hostile
    v = verify_files_in(tmp_path, s.bundle.files, plan_digest=frozen.plan_digest)
    assert v.accepted and not v.findings and v.exit_code == K.EXIT_ENVIRONMENT, [f.to_json() for f in v.findings]


# ---- hiding the refusal or claiming more is rejected ------------------------------------------------------------------------------------
def _lane(fn):
    return lambda up, files: forge_consistently(up, files, edit_lane=lambda lid, o: fn(o) if lid == "robot" else o)


def _strip_denials(data):
    lines = [l for l in data.decode().splitlines()]
    kept = [lines[0]] + [l for l in lines[1:] if '"verdict":"deny"' not in l]
    rows = [json.loads(l) for l in kept]
    for i, row in enumerate(rows[1:], 1):
        row["seq"] = i                                              # the forger renumbers: the file is well formed, only the refusals are gone
    return ("\n".join(json.dumps(r, sort_keys=True, separators=(",", ":")) for r in rows) + "\n").encode()


def _edit_log(fn):
    def mutate(o):
        files = dict(o.files)
        data, role = files["lanes/robot/egress-log.jsonl"]
        files["lanes/robot/egress-log.jsonl"] = (fn(data), role)
        return replace(o, files=files)
    return mutate


def _edit_header(**changes):
    def fn(data):
        lines = data.decode().splitlines()
        head = json.loads(lines[0])
        head.update(changes)
        return ("\n".join([json.dumps(head, sort_keys=True, separators=(",", ":"))] + lines[1:]) + "\n").encode()
    return fn


def _add_allow(data):
    row = {"seq": len(data.decode().splitlines()), "layer": egresslog.LAYER_SECCOMP, "syscall": "connect", "verdict": "allow", "reason": "in-allow-list", "family": "AF_INET", "address": "8.8.8.8", "port": 53}
    return data + (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()


CASES = [
    ("the lane relabelled as a completed pass, everything recomputed", _lane(lambda o: replace(o, native_status="NATIVE_PASS", raw_status="PASS", exit_code=0, counts={"passed": 1, "failed": 0, "errored": 0, "skipped": 0})),
     ("EGRESS_DENIAL_NOT_REFLECTED",)),
    ("the refusals removed from the log, the lane still says egress-denied", _lane(_edit_log(_strip_denials)), ("EGRESS_DENIAL_NOT_IN_LOG",)),
    ("the log removed from the bundle, the lane still says egress-denied", _lane(lambda o: replace(o, files={k: v for k, v in o.files.items() if not k.endswith("egress-log.jsonl")})), ("EGRESS_DENIAL_NOT_IN_LOG",)),
    ("the log claims only one layer was installed", _lane(_edit_log(_edit_header(layers=[egresslog.LAYER_SECCOMP]))), ("EGRESS_MECHANISM_WRONG",)),
    ("the log claims another allow-list", _lane(_edit_log(_edit_header(allowed=["127.0.0.1/32:1"]))), ("EGRESS_MECHANISM_WRONG",)),
    ("the log claims a self-test that did not pass", _lane(_edit_log(_edit_header(selftest={"forbidden_tcp_refused": False, "udp_refused": True}))), ("EGRESS_MECHANISM_WRONG",)),
    ("an allowed connect to an address outside the allow-list added to the log", _lane(_edit_log(_add_allow)), ("EGRESS_ALLOW_OUTSIDE_POLICY",)),
    ("a record of the log that is not a decision", _lane(_edit_log(lambda d: d + b'{"nonsense":1}\n')), ("EGRESS_LOG_MALFORMED",)),
]


@pytest.mark.parametrize("name,mutate,expect", CASES, ids=[c[0] for c in CASES])
def test_every_edit_that_hides_a_refusal_or_overstates_the_layers_is_rejected_with_the_finding_that_names_it(hostile, up, tmp_path, name, mutate, expect):
    frozen, s, _ = hostile
    v = verify_files_in(tmp_path, mutate(up, dict(s.bundle.files)))
    assert not v.accepted and set(expect) <= set(codes(v)), (name, codes(v))


def test_a_verified_verdict_written_into_the_report_of_the_refused_lane_is_rejected(hostile, up, tmp_path):
    """The adapter-claimed VERIFIED: the report is edited to say the refused lane's assertion is VERIFIED (and the manifest rechained)."""
    frozen, s, _ = hostile

    def fn(r):
        for x in r["accounting"]["results"]:
            x["verdict"].update(state="VERIFIED", reason_code="EQUALS_EXPECTED")
    v = verify_files_in(tmp_path, rechain(edit_json(dict(s.bundle.files), "report.json", fn)))
    assert not v.accepted and "VERDICT_RECOMPUTE_MISMATCH" in codes(v)


def test_the_extension_count_cannot_be_changed_and_the_statement_cannot_be_swapped_for_the_old_one(hostile, up, tmp_path):
    frozen, s, _ = hostile
    v = verify_files_in(tmp_path, rechain(edit_json(dict(s.bundle.files), "report.json", lambda r: r["extensions"].update(egress_fence_denied=0))))
    assert not v.accepted and "REPORT_FIELD_MISMATCH" in codes(v)
    v = verify_files_in(tmp_path, rechain(edit_json(dict(s.bundle.files), "report.json", lambda r: [x.update(id=K.ROBOT_EGRESS_LIMITATION_ID, text=K.robot_egress_limitation_text(["robot"])) for x in r["limitations"]
                                                                                                if x["id"] == K.ROBOT_EGRESS_LAYERS_ID])))
    assert not v.accepted and "EGRESS_STATEMENT_WRONG" in codes(v)
