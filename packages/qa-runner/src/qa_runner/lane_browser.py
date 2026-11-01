# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The browser lane, as a child process: ``python -m qa_runner.lane_browser INPUT.json``.

It wires the harness executor (``QARunner``) to the real ``PlaywrightAdapter`` over real Chromium, with the egress gateway in front of the browser,
runs ONE materialised spec, and writes what happened into ``out_dir``: the harness run record, the redacted blobs, the gateway log and
``lane-result.json``. It never judges anything for the bundle: the observed values it records are what the adapter returned to the harness verifier;
the verdicts in the report are computed afterwards by ``qa_runner.judge`` over those observations and the frozen assertions.

The parent supervises this process: a deadline, a cancel and an output limit end the whole process group (this process, its gateway threads and the browser).
"""
from __future__ import annotations

import copy
import json
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from qa_evidence.canon import CanonError, dumps_canonical, loads_strict

from . import constants as K
from .deps import bootstrap


class AppChecks:
    """The attestations ``QARunner`` needs before and after a run, answered from facts: the fixture app's own health endpoint. A spec that declares
    preconditions or fixtures gets ``None`` (unknown), which the harness classifier treats as 'cannot pass', because nothing here can attest them."""

    def __init__(self, origin: str):
        self._origin = origin
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))      # direct: the health probe is not browser traffic

    def environment_healthy(self, phase: str) -> Optional[bool]:
        try:
            with self._opener.open(self._origin + "/health", timeout=3) as resp:
                return resp.status == 200 and json.loads(resp.read(4096).decode("utf-8")).get("status") == "ok"
        except Exception:
            return False

    def preconditions_met(self, spec) -> Optional[bool]:
        return True if not spec.preconditions else None

    def fixtures_match(self, spec) -> Optional[bool]:
        return True if not spec.fixtures else None


class RecordingAdapter:
    """Delegates everything to the real adapter and keeps what ``assert_`` returned (the harness verifier's only read of the page), in call order."""

    def __init__(self, inner: Any):
        self._inner = inner
        self.reads: List[Dict[str, Any]] = []
        self.guard_decisions: List[Any] = []              # the in-browser request gate's decisions (the second egress layer), taken before the session closes
        self.guard_counts: Dict[str, Any] = {}

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def assert_(self, session: Any, subject: Any) -> Any:
        observed = self._inner.assert_(session, subject)
        self.reads.append({"subject": subject.to_json(), "observed": observed})
        return observed


    def close_session(self, handle: Any) -> Any:
        try:
            self.guard_decisions.extend(self._inner.egress_decisions(handle))
            self.guard_counts = self._inner.egress_counts(handle)
        except Exception:
            pass                                          # a session that is already lost has nothing to drain; the close itself still happens
        return self._inner.close_session(handle)


def observation_row(observed: Any) -> Dict[str, Any]:
    return {"resolution": observed.resolution.value, "match_count": int(observed.match_count), "value": observed.value,
            "value_digest": observed.value_digest}


def _write(out: Path, name: str, data: bytes) -> None:
    target = out / name
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "xb") as fh:
        fh.write(data)


def run_lane(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Run the lane described by ``cfg`` (see ``orchestrate.lane_input``) and return the lane result document. Raises on an environment failure."""
    up = bootstrap()
    h = up.harness
    from qa_egress import GatewayServer, build_launch_config
    from qa_egress.resolver import SystemResolver
    from qa_playwright import AdapterConfig, EgressProfile, PlaywrightAdapter, PlaywrightDriver, ProxySettings

    out = Path(cfg["out_dir"])
    out.mkdir(parents=True, exist_ok=True)
    spec = h.records.TestSpec.from_json(copy.deepcopy(cfg["spec"]))
    assertions = tuple(h.records.AssertionSpec.from_json(copy.deepcopy(a)) for a in cfg["assertions"])
    pin = h.verifier.assertion_set_pin(assertions)
    if pin != cfg["harness_pin"]:
        raise RuntimeError("the assertions handed to the lane are not the frozen ones (pin mismatch)")
    origin = cfg["origin"]
    egress_policy = h.egress.EgressPolicy.from_config(cfg["egress_policy"])
    resolver = SystemResolver()
    redactor = h.redaction.PatternRedactor(h.redaction.RedactionConfig(acknowledged_unredacted_media=("image/png",)))
    blobs = h.blobs.MemoryBlobSink()
    clock = h.clock.SystemClock()
    started = time.monotonic()
    gateway = GatewayServer(egress_policy, resolver).start()
    adapter = None
    try:
        fields = build_launch_config("127.0.0.1", gateway.port).profile_fields()
        profile = EgressProfile("lane", egress_policy, resolver, tuple(fields["launch_args"]), ProxySettings(**fields["proxy"]))
        real = PlaywrightAdapter(PlaywrightDriver(), blobs=blobs, redactor=redactor, clock=clock, egress_profiles={"lane": profile}, config=AdapterConfig())
        adapter = RecordingAdapter(real)
        policy = h.policy.DefaultActionPolicy(spec=spec, allowed_action_kinds=[h.records.ActionKind(k) for k in K.ALLOWED_ACTION_KINDS], allowed_origins=[origin], clock=clock)
        stream = h.hooks.MemoryEvidenceStream()
        runner = h.runner.QARunner(
            qa_adapter=adapter, policy=policy, store=h.specstore.InMemorySpecStore({pin: [copy.deepcopy(a) for a in cfg["assertions"]]}),
            lineage=h.verifier.ApprovedLineage([pin]), programs=h.specstore.InMemoryProgramRegistry({}), clock=clock,
            config=h.runner.RunConfig(egress_policy_id=egress_policy.policy_id, redaction_policy_id=redactor.policy_id),
            evidence=stream, checks=AppChecks(origin), egress=h.egress.EgressGuard(egress_policy, resolver))
        try:
            result = runner.run(spec, run_id=cfg["run_id"], pinned_assertion_set_hash=pin)
        finally:
            real.shutdown()
        gateway.wait_idle()
        gateway_events = gateway.events()
    finally:
        gateway.stop()
    ordered = sorted(assertions, key=lambda a: a.assertion_id)
    reads = adapter.reads if adapter is not None else []
    observations = []
    for assertion, read in zip(ordered, reads):
        if read["subject"] != assertion.subject.to_json():
            break                                            # the harness did not read the subjects in the order the frozen set lists them: record nothing it cannot pair
        observations.append({"assertion_id": assertion.assertion_id, **observation_row(read["observed"])})
    record = {"schema": "redevops-qa/harness-run-record", "schema_version": K.SCHEMA_VERSION, "run_id": result.run_id, "manifest": result.manifest.to_json(with_hash=True),
              "events": [dict(e) for e in result.events], "receipts": [r.to_json(with_hash=True) for r in result.receipts],
              "receipt_links": [{"index": l.index, "receipt_hash": l.receipt_hash, "prev": l.prev, "link_hash": l.link_hash} for l in result.receipt_links],
              "classification": result.classification.to_json(), "states": [s.value for s in result.states], "exit_code": result.exit_code,
              "cancelled": result.cancelled, "sealed": result.sealed}
    _write(out, "run-record.json", dumps_canonical(json.loads(json.dumps(record, default=str))))
    for digest in blobs.digests():
        _write(out, "blobs/" + digest.split(":", 1)[1], blobs.get(digest))
    log = "".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in gateway_events).encode("utf-8")
    _write(out, "gateway-log.jsonl", log)
    guard_log = "".join(json.dumps({"decision": d.to_json(), "decision_hash": d.record_hash}, sort_keys=True, separators=(",", ":")) + "\n"
                        for d in (adapter.guard_decisions if adapter is not None else [])).encode("utf-8")
    _write(out, "browser-guard-log.jsonl", guard_log)
    guard_denied = sum(1 for d in (adapter.guard_decisions if adapter is not None else []) if d.verdict.value != "ALLOW")
    verdicts = [{"assertion_id": r.assertion_id, "verdict": r.check.verdict.value, "reason_code": r.reason_code, "actual": r.actual, "actual_digest": r.actual_digest}
                for r in result.manifest.assertion_results]
    counts = {"events": len(gateway_events), "allowed": sum(1 for e in gateway_events if e.get("decision", {}).get("verdict") == "ALLOW" and e.get("request_kind") != "redirect"),
              "denied": sum(1 for e in gateway_events if e.get("outcome") == "denied" or e.get("decision", {}).get("verdict", "ALLOW") != "ALLOW")}
    doc = {"schema": K.LANE_RESULT_SCHEMA, "schema_version": K.SCHEMA_VERSION, "status": "COMPLETED", "outcome": result.outcome.value, "reason": result.classification.reason,
           "exit_code": result.exit_code, "sealed": result.sealed, "cancelled": result.cancelled, "states": [s.value for s in result.states],
           "browser": result.manifest.browser, "observations": observations, "harness_verdicts": verdicts, "gateway": counts, "browser_guard": {"decisions": len(adapter.guard_decisions) if adapter is not None else 0, "denied": guard_denied},
           "seconds_milli": int((time.monotonic() - started) * 1000)}
    _write(out, "lane-result.json", dumps_canonical(json.loads(json.dumps(doc, default=str))))
    return doc


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m qa_runner.lane_browser INPUT.json", file=sys.stderr)
        return 2
    try:
        cfg = loads_strict(Path(argv[0]).read_bytes())
    except (OSError, CanonError) as exc:
        print(f"lane input unreadable: {type(exc).__name__}", file=sys.stderr)
        return 2
    try:
        if cfg.get("schema") != K.LANE_INPUT_SCHEMA:
            raise ValueError("not a lane input")
        if isinstance(cfg.get("parent_pid"), int):
            from . import watchdog
            watchdog.start(cfg["parent_pid"], watchdog.kill_own_group)       # the orchestrator died: end this process, its gateway and its browser
        run_lane(cfg)
        return 0
    except Exception as exc:
        # An environment or wiring failure: say what kind, write it where the parent looks, and exit non-zero. The text of the exception is untrusted
        # (it may carry page or path content), so only its class is kept in the result and the full detail goes to standard error for the logs.
        out = Path(cfg.get("out_dir", "."))
        try:
            out.mkdir(parents=True, exist_ok=True)
            doc = {"schema": K.LANE_RESULT_SCHEMA, "schema_version": K.SCHEMA_VERSION, "status": "ERROR", "error_class": type(exc).__name__}
            with open(out / "lane-result.json", "xb") as fh:
                fh.write(dumps_canonical(doc))
        except OSError:
            pass
        print(f"lane failed: {type(exc).__name__}: {str(exc)[:500]}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
