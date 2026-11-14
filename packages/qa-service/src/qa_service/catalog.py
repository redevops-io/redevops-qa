# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""What can be run (profiles, code-defined and shipped with the image), against what (targets, operator-registered) and what a run would do (estimates).

A client chooses a profile id and a target id. It never supplies a plan, a path, a URL to open or a command: the plan an estimate or a run uses is built here, from a shipped file or from the
template below with the origin of a REGISTERED target."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import subprocess
import tempfile
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import capabilities as caps
from .config import Config

TARGET_ID_RE = re.compile(r"^tgt-[0-9a-f]{12}$")
PROFILE_ID_RE = re.compile(r"^[a-z0-9-]{1,40}$")
FIXTURE_TARGET_ID = "tgt-000000000000"
ESTIMATE_TTL_S = 3600

#: profile id -> definition. ``plan`` is the legacy plan name of /v1/runs (``{"plan": "browser"}`` keeps working); ``plan_file`` is the shipped plan the estimate is made from (None: the template).
PROFILES: Dict[str, Dict[str, Any]] = {
    "fixture-demo": {"plan": "demo", "title": "Demo: browser lane, then Robot lane", "description": "Playwright Chromium and Robot Framework against the bundled fixture app (a seeded defect can be chosen).",
                     "engines": ["playwright", "robot"], "targets": ["fixture-app"], "plan_file": "demo-plan.json", "est_duration_s": 60},
    "fixture-browser": {"plan": "browser", "title": "Browser lane", "description": "Playwright Chromium against the bundled fixture app.", "engines": ["playwright"], "targets": ["fixture-app"],
                        "plan_file": "golden-plan.json", "est_duration_s": 20},
    "fixture-robot": {"plan": "robot", "title": "Robot lane (kernel layers)", "description": "Robot Framework with its egress limited by Landlock and seccomp.", "engines": ["robot"], "targets": ["fixture-app"],
                      "plan_file": "robot-plan.json", "est_duration_s": 20},
    "fixture-robot-not-enforced": {"plan": "robot-not-enforced", "title": "Robot lane (egress not enforced)", "description": "Robot Framework with no limit on its traffic; the report says so.",
                                   "engines": ["robot"], "targets": ["fixture-app"], "plan_file": "robot-plan-not-enforced.json", "est_duration_s": 20},
    "edge-sentinel-fixture-readonly": {"plan": None, "title": "Edge Sentinel fixture mode (read-only)", "description": "A read-only journey against a loopback Edge Sentinel started with EDGE_SENTINEL_DEMO=1.",
                                       "engines": ["playwright"], "targets": ["external-origin"], "plan_file": None, "est_duration_s": 20},
}
LEGACY_PLAN_TO_PROFILE = {v["plan"]: k for k, v in PROFILES.items() if v["plan"]}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical(doc: Any) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(doc: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(doc)).hexdigest()


def edge_sentinel_plan(origin: str, plans_dir: Path) -> Dict[str, Any]:
    """The read-only journey of the ``edge-sentinel-fixture-readonly`` profile: the plan the runner ships as ``examples/edge-sentinel-fixture-plan.json`` (open /health of the origin, assert the URL),
    with the origin of a REGISTERED target put in its target. A client never supplies a plan."""
    plan = json.loads((plans_dir / "edge-sentinel-fixture-plan.json").read_text(encoding="utf-8"))
    plan["target"] = {"kind": "external-origin", "origin": origin, "declared_by": "operator", "credential_refs": [], "mutating": False}
    return plan


class CatalogError(Exception):
    def __init__(self, status: int, code: str, message: str, **extra: Any):
        super().__init__(message)
        self.status, self.code, self.extra = status, code, extra


class Targets:
    """``targets.json`` in the data directory (atomic, 0600). The built-in fixture target is not stored and cannot be changed."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.path = cfg.data_dir / "targets.json"
        self._lock = threading.Lock()

    def _read(self) -> List[Dict[str, Any]]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))["targets"]
        except (OSError, ValueError, KeyError):
            return []

    def _write(self, items: List[Dict[str, Any]]) -> None:
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"version": 1, "targets": items}, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, self.path)

    def builtin(self) -> Dict[str, Any]:
        return {"id": FIXTURE_TARGET_ID, "name": "fixture app (built in)", "kind": "fixture-app", "origin": None, "declared_by": "operator", "declared_at": None, "declared_user": None,
                "egress_profile": "origin-only", "credential_refs": [], "mutating": False, "run_approval": "none", "level_ceiling": "VERIFIED", "builtin": True, "notes": "started by the runner on loopback for each run",
                "last_probe": None}

    def list(self) -> List[Dict[str, Any]]:
        return [self.builtin()] + self._read()

    def get(self, target_id: str) -> Optional[Dict[str, Any]]:
        return next((t for t in self.list() if t["id"] == target_id), None)

    def register(self, spec: Dict[str, Any], *, user: str, estimate: "Estimator") -> Dict[str, Any]:
        unknown = sorted(set(spec) - {"name", "origin", "run_approval", "notes"})
        if unknown:
            raise CatalogError(422, "invalid", "only name, origin, run_approval and notes are accepted", field=unknown[0])
        name = spec.get("name")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80 or any(ord(c) < 32 for c in name):
            raise CatalogError(422, "invalid", "name is 1 to 80 printable characters", field="name")
        approval = spec.get("run_approval", "required" if spec.get("origin") else "none")
        if approval not in ("required", "none"):
            raise CatalogError(422, "invalid", "run_approval is required or none", field="run_approval")
        notes = str(spec.get("notes", ""))[:300]
        origin = spec.get("origin")
        if origin is None:
            kind, probe, ceiling = "fixture-app", None, "VERIFIED"
        else:
            kind, ceiling = "external-origin", "CORROBORATED"
            if approval != "required":
                raise CatalogError(422, "invalid", "an external-origin target always requires approval for a run", field="run_approval")
            if not isinstance(origin, str):
                raise CatalogError(422, "invalid", "origin is a string", field="origin")
            doc = estimate.run_cli_estimate(edge_sentinel_plan(origin, estimate.cfg.plans_dir))          # the SAME validator as `freeze`: its refusal is the answer
            codes = {p["code"] for p in doc.get("problems", [])}
            if "TARGET_OUT_OF_SCOPE" in codes:
                raise CatalogError(422, "TARGET_OUT_OF_SCOPE", next(p["message"] for p in doc["problems"] if p["code"] == "TARGET_OUT_OF_SCOPE"), field="origin")
            probe = self.probe_fixture_mode(origin)
            if not probe["ok"]:
                raise CatalogError(422, "NOT_FIXTURE_MODE", "the target did not present itself as Edge Sentinel fixture mode (/health must report demo.enabled=true): " + probe["detail"], field="origin")
        target = {"id": "tgt-" + secrets.token_hex(6), "name": name.strip(), "kind": kind, "origin": origin, "declared_by": "operator", "declared_at": iso(_now()), "declared_user": user,
                  "egress_profile": "origin-only", "credential_refs": [], "mutating": False, "run_approval": approval, "level_ceiling": ceiling, "builtin": False, "notes": notes, "last_probe": probe}
        with self._lock:
            items = self._read()
            if any(t["name"] == target["name"] for t in items):
                raise CatalogError(409, "conflict", "a target with that name exists", field="name")
            items.append(target)
            self._write(items)
        return target

    @staticmethod
    def probe_fixture_mode(origin: str) -> Dict[str, Any]:
        """One GET /health of the registered loopback origin (the scope gate has already limited it to http://127.0.0.1:<port>): fixture mode must be reported before anything runs."""
        at = iso(_now())
        try:
            req = urllib.request.Request(origin + "/health", headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=3) as resp:       # nosec: the origin was validated as http://127.0.0.1:<port>
                body = json.loads(resp.read(65536).decode("utf-8"))
            demo = body.get("demo") if isinstance(body, dict) else None
            ok = isinstance(demo, dict) and demo.get("enabled") is True
            return {"at": at, "ok": ok, "detail": "demo.enabled=true" if ok else "demo.enabled is not true"}
        except Exception as exc:
            return {"at": at, "ok": False, "detail": f"/health could not be read ({type(exc).__name__})"}

    def delete(self, target_id: str, *, in_use: bool) -> None:
        if target_id == FIXTURE_TARGET_ID:
            raise CatalogError(409, "conflict", "the built-in fixture target cannot be removed")
        if in_use:
            raise CatalogError(409, "conflict", "a run uses this target")
        with self._lock:
            items = self._read()
            rest = [t for t in items if t["id"] != target_id]
            if len(rest) == len(items):
                raise CatalogError(404, "not_found", "no such target")
            self._write(rest)


class Estimator:
    """``POST /v1/estimates``: ``redevops-qa estimate`` over the plan this service builds for (target, profile); nothing is contacted and nothing but the estimate is written."""

    def __init__(self, cfg: Config, facts: caps.Facts):
        self.cfg, self.facts = cfg, facts
        self.dir = cfg.data_dir / "estimates"
        self.dir.mkdir(parents=True, exist_ok=True)

    def plan_for(self, target: Dict[str, Any], profile: str) -> Dict[str, Any]:
        p = PROFILES[profile]
        if target["kind"] == "external-origin":
            return edge_sentinel_plan(target["origin"], self.cfg.plans_dir)
        return json.loads((self.cfg.plans_dir / p["plan_file"]).read_text(encoding="utf-8"))

    def run_cli_estimate(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        with tempfile.TemporaryDirectory(dir=str(self.cfg.data_dir / "tmp") if (self.cfg.data_dir / "tmp").is_dir() else None) as tmp:
            path = Path(tmp) / "plan.json"
            path.write_text(json.dumps(plan), encoding="utf-8")
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": tmp, "LANG": "C.UTF-8"}
            for key in ("REDEVOPS_QA_PINS", "PLAYWRIGHT_BROWSERS_PATH", "TMPDIR", "PYTHONPATH"):
                if key in os.environ and key != "PYTHONPATH":
                    env[key] = os.environ[key]
            done = subprocess.run([self.cfg.cli, "estimate", str(path)], capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL, env=env, cwd=tmp, check=False)
        if done.returncode != 0:
            msg = (done.stderr or "").strip().splitlines()[-1:] or ["the plan was refused"]
            raise CatalogError(422, "invalid", msg[0].replace("error: ", "", 1)[:400], field="origin")
        try:
            return json.loads(done.stdout)
        except ValueError:
            raise CatalogError(502, "estimate_failed", "the estimate command printed no JSON") from None

    def create(self, target: Dict[str, Any], profile: str, unavailable: Optional[Dict[str, str]]) -> Dict[str, Any]:
        plan = self.plan_for(target, profile)
        doc = self.run_cli_estimate(plan)
        doc["target_id"], doc["profile"] = target["id"], profile
        problems = list(doc.get("problems", []))
        if unavailable:
            problems.append({"code": unavailable["code"], "message": unavailable["reason"]})
        doc["problems"], doc["will_refuse"] = problems, bool(problems)
        d = digest(doc)
        est = {"estimate_id": "est-" + secrets.token_hex(6), "digest": d, "created": iso(_now()), "expires": iso(_now() + timedelta(seconds=ESTIMATE_TTL_S)), **{k: doc[k] for k in (
            "target_id", "profile", "plan_id", "plan_digest", "engines", "lanes", "limits", "credential_refs", "problems", "will_refuse", "verification_ceiling", "contacts", "platform")},
            "origin": doc["target"].get("origin"), "egress_policy_digest": doc.get("egress_policy_digest"), "lane_deadlines": {l["lane_id"]: l["deadline_s"] for l in doc["lanes"]}}
        (self.dir / (est["estimate_id"] + ".json")).write_text(json.dumps(est, indent=2, sort_keys=True), encoding="utf-8")
        return est

    def find_valid(self, target_id: str, profile: str, est_digest: str) -> Optional[Dict[str, Any]]:
        """A stored, unexpired estimate for exactly this target and profile with this digest (the digest binds what the person saw)."""
        for path in sorted(self.dir.glob("est-*.json")):
            try:
                est = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if est.get("digest") == est_digest and est.get("target_id") == target_id and est.get("profile") == profile and est.get("expires", "") > iso(_now()):
                return est
        return None
