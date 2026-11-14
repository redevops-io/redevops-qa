# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Runs of the ``redevops-qa`` command, one at a time, and what they leave on disk.

Layout under the data directory::

    runs/<run id>/status.json     the run record (written atomically; see RECORD_KEYS)
    runs/<run id>/events.jsonl    append-only progress events, one JSON object per line, ``seq`` 1, 2, 3...
    runs/<run id>/output.txt      standard output and error of the command
    runs/<run id>/evidence/<id>/  the evidence bundle the command wrote

A run is started for a (target, profile) the service knows: no request names a file, a URL or a command. A target that requires approval (every external target, and a fixture target an admin
marked so) is created ``awaiting_approval`` with the digest of the estimate the approver saw; nothing starts until a user with the operator role approves THAT digest."""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import capabilities as caps
from . import catalog
from .config import Config

RUN_ID_RE = re.compile(r"^r[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$")
DEFECTS = ("none", "discount", "settings")
#: legacy plan name -> (command, plan file, packages): what the four shipped plans are (kept: ``POST /v1/runs {"plan": "browser"}`` still works)
PLANS = {k: v[:3] for k, v in caps.PLANS.items()}
#: the runner's exit status table (packages/qa-runner/README.md)
EXIT_MEANING = {0: "VERIFIED", 1: "FAILED", 2: "REFUSED", 3: "NOT_COMPLETED", 4: "INCONCLUSIVE", 5: "EVIDENCE_REJECTED", 6: "RUNNER_ERROR", 7: "VERIFIER_UNAVAILABLE", 8: "CORROBORATED"}
TERMINAL = ("finished", "failed_to_start", "timed_out", "interrupted", "cancelled", "refused")
OUTPUT_LIMIT = 1 << 20


class Busy(Exception):
    def __init__(self, active: str):
        super().__init__(active)
        self.active = active


class Refused(Exception):
    def __init__(self, code: str, message: str, unavailable: Optional[Dict[str, str]] = None, status: int = 400, **extra: Any):
        super().__init__(message)
        self.code, self.unavailable, self.status, self.extra = code, unavailable, status, extra


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("r%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)


def level_for(outcome: Optional[str], ceiling: str) -> Optional[str]:
    """The verification level a finished run may print: the runner's own outcome, capped by the target's ceiling (an external target never reaches VERIFIED)."""
    if outcome in ("VERIFIED", "CORROBORATED"):
        return "VERIFIED" if (outcome == "VERIFIED" and ceiling == "VERIFIED") else "CORROBORATED"          # the runner already caps an external run; the cap is applied here too
    return None


class RunStore:
    def __init__(self, cfg: Config, facts: Optional[caps.Facts] = None):
        self.cfg = cfg
        self.facts = facts if facts is not None else caps.collect()
        self.root = cfg.data_dir / "runs"
        self._lock = threading.Lock()
        self._active: Optional[str] = None
        self._procs: Dict[str, subprocess.Popen] = {}
        self._cancelled: set = set()
        self.root.mkdir(parents=True, exist_ok=True)
        self.targets = catalog.Targets(cfg)
        self.estimator = catalog.Estimator(cfg, self.facts)
        self._mark_interrupted()

    # ------------------------------------------------------------------ files
    def _dir(self, run_id: str) -> Path:
        if not RUN_ID_RE.fullmatch(run_id):
            raise KeyError(run_id)
        return self.root / run_id

    def _write_status(self, run_id: str, record: Dict[str, Any]) -> None:
        d = self.root / run_id
        tmp = d / "status.json.tmp"
        tmp.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, d / "status.json")

    def event(self, run_id: str, type_: str, label: str = "", **detail: Any) -> Dict[str, Any]:
        path = self.root / run_id / "events.jsonl"
        with self._lock:
            seq = 1
            try:
                with open(path, "rb") as fh:
                    seq = sum(1 for _ in fh) + 1
            except OSError:
                pass
            ev = {"seq": seq, "at": _now(), "type": type_, "lane": detail.pop("lane", None), "engine": detail.pop("engine", None), "step": None, "total": None, "label": str(label)[:120], "detail": detail}
            with open(path, "ab") as fh:
                fh.write((json.dumps(ev, sort_keys=True) + "\n").encode("utf-8"))
        return ev

    def events(self, run_id: str, after: int = 0, limit: int = 100) -> Dict[str, Any]:
        rec = self.get(run_id)
        items: List[Dict[str, Any]] = []
        head = 0
        try:
            with open(self._dir(run_id) / "events.jsonl", "rb") as fh:
                for line in fh:
                    try:
                        ev = json.loads(line)
                    except ValueError:
                        continue
                    head = max(head, ev["seq"])
                    if ev["seq"] > after and len(items) < limit:
                        items.append(ev)
        except OSError:
            pass
        return {"items": items, "head": head, "terminal": rec["state"] in TERMINAL}

    def get(self, run_id: str) -> Dict[str, Any]:
        try:
            return json.loads((self._dir(run_id) / "status.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise KeyError(run_id) from None

    def list(self, limit: int = 100, *, cursor: Optional[str] = None, **filters: Optional[str]) -> Dict[str, Any]:
        ids = sorted((p.name for p in self.root.iterdir() if RUN_ID_RE.fullmatch(p.name)), reverse=True)
        if cursor:
            try:
                last = base64.b64decode(cursor.encode(), altchars=b"-_", validate=True).decode()
                if not RUN_ID_RE.fullmatch(last):
                    raise ValueError
            except Exception:
                raise Refused("invalid", "cursor is not valid", status=422, field="cursor") from None
            ids = [i for i in ids if i < last]
        items: List[Dict[str, Any]] = []
        for i in ids:
            try:
                rec = self.get(i)
            except KeyError:
                continue
            if all(v is None or rec.get(k) == v for k, v in filters.items()):
                items.append(rec)
            if len(items) > limit:
                break
        more = len(items) > limit
        items = items[:limit]
        return {"items": items, "next_cursor": base64.urlsafe_b64encode(items[-1]["id"].encode()).decode() if more and items else None}

    def _mark_interrupted(self) -> None:
        """A run that was going when the service stopped cannot be resumed: say so instead of leaving it 'running' for ever."""
        for rec in self.list(10000)["items"]:
            if rec.get("state") in ("running", "queued"):
                rec.update(state="interrupted", finished=_now(), note="the service stopped while this run was going; its evidence directory, if any, is incomplete")
                self._write_status(rec["id"], rec)
                self.event(rec["id"], "run.interrupted", "the service stopped while this run was going")

    # ------------------------------------------------------------------ availability
    def profile_unavailable(self, profile: str, target: Dict[str, Any]) -> Optional[Dict[str, str]]:
        if target["kind"] == "external-origin":
            return caps.unavailable("browser", self.facts, self.cfg.plans_dir)          # the Playwright lane, its pinned browser and the platform; the runner checks fixture mode itself
        legacy = catalog.PROFILES[profile]["plan"]
        return caps.unavailable(legacy, self.facts, self.cfg.plans_dir)

    def availability(self) -> Dict[str, Dict[str, Any]]:
        """legacy plan name -> {"available", "unavailable"} (the shape /v1/info has had since 0.6.2)"""
        out: Dict[str, Dict[str, Any]] = {}
        for name in PLANS:
            why = caps.unavailable(name, self.facts, self.cfg.plans_dir)
            out[name] = {"available": why is None, "unavailable": why}
        return out

    def profiles(self, target: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        out = []
        for pid, p in catalog.PROFILES.items():
            kinds = p["targets"]
            entry = {"id": pid, "title": p["title"], "description": p["description"], "engines": p["engines"], "targets": kinds, "mutating": False, "est_duration_s": p["est_duration_s"]}
            if "external-origin" in kinds:
                why = caps.unavailable("browser", self.facts, self.cfg.plans_dir)
            else:
                why = caps.unavailable(p["plan"], self.facts, self.cfg.plans_dir)
            entry["available"] = why is None
            entry["unavailable"] = why
            if target is not None and target["kind"] not in kinds:
                entry["available"], entry["unavailable"] = False, {"code": "TARGET_KIND_MISMATCH", "reason": f"this profile runs against a {' or '.join(kinds)} target, not {target['kind']}", "remedy": "choose a profile for this target"}
            out.append(entry)
        return out

    # ------------------------------------------------------------------ starting a run
    def start(self, plan: Optional[str] = None, defect: str = "none", *, target_id: Optional[str] = None, profile: Optional[str] = None, estimate_digest: Optional[str] = None,
              user: str = "service", via: str = "service") -> Dict[str, Any]:
        if profile is None:
            if plan not in PLANS:
                raise Refused("unknown_plan", "plan must be one of: " + ", ".join(sorted(PLANS)), status=400)
            profile = catalog.LEGACY_PLAN_TO_PROFILE[plan]
        if profile not in catalog.PROFILES:
            raise Refused("invalid", "unknown profile", status=422, field="profile")
        if defect not in DEFECTS:
            raise Refused("unknown_defect", "defect must be one of: " + ", ".join(DEFECTS), status=400)
        target = self.targets.get(target_id or catalog.FIXTURE_TARGET_ID)
        if target is None:
            raise Refused("not_found", "no such target", status=404)
        if target["kind"] == "external-origin" and defect != "none":
            raise Refused("invalid", "a seeded defect applies to the fixture target only", status=422, field="defect")
        why = self.profile_unavailable(profile, target)
        if why is None and target["kind"] not in catalog.PROFILES[profile]["targets"]:
            why = {"code": "TARGET_KIND_MISMATCH", "reason": f"this profile does not run against a {target['kind']} target", "remedy": "choose a profile for this target"}
        if why is not None:
            raise Refused("plan_unavailable", why["reason"], why, status=422)
        approval_required = target["run_approval"] == "required"
        est = None
        if approval_required:
            est = self.estimator.find_valid(target["id"], profile, estimate_digest or "")
            if est is None:
                raise Refused("estimate_required", "this target requires approval: create an estimate for this target and profile (POST /v1/estimates) and pass its digest as estimate_digest", status=422, field="estimate_digest")
            if est["will_refuse"]:
                raise Refused("estimate_refuses", "the estimate lists reasons a run would refuse; nothing is started", status=422, problems=est["problems"])
        with self._lock:
            if not approval_required and self._active is not None:
                raise Busy(self._active)
            run_id = new_run_id()
            d = self.root / run_id
            d.mkdir(parents=True)
            (d / "evidence").mkdir()
            state = "awaiting_approval" if approval_required else "running"
            record = {"id": run_id, "plan": catalog.PROFILES[profile]["plan"], "defect": defect, "target_id": target["id"], "profile": profile, "state": state, "created": _now(),
                      "started": None if approval_required else _now(), "finished": None, "exit_code": None, "outcome": None, "level": None, "level_ceiling": target["level_ceiling"],
                      "bundle": None, "estimate_digest": est["digest"] if est else None, "approval": {"required": approval_required, "state": "pending" if approval_required else None, "actor_user": None,
                      "actor_role": None, "via": None, "at": None, "rationale": None} if approval_required else None, "requested_by": {"user": user, "via": via}, "progress": None, "note": None}
            self._write_status(run_id, record)
            if not approval_required:
                self._active = run_id
        self.event(run_id, "run.queued", f"profile {profile} on target {target['id']}")
        if approval_required:
            self.event(run_id, "run.approval_requested", "waiting for an operator to approve the estimate", estimate_digest=record["estimate_digest"])
        else:
            self._launch(run_id, profile, defect)
        return record

    def approve(self, run_id: str, approved: bool, estimate_digest: str, *, user: str, role: str, via: str, rationale: str = "", two_person: bool = False, external_actor: Optional[str] = None) -> Dict[str, Any]:
        rec = self.get(run_id)
        if rec["state"] != "awaiting_approval":
            raise Refused("conflict", "the run is not waiting for approval", status=409)
        if two_person and user == rec["requested_by"]["user"]:
            raise Refused("forbidden", "the person who requested the run cannot approve it (two-person rule)", status=403)
        if estimate_digest != rec["estimate_digest"]:
            raise Refused("stale_approval", "the digest is not the estimate this run was created from: the approval is void", status=409)
        stamp = {"state": "approved" if approved else "rejected", "actor_user": user, "actor_role": role, "via": via, "at": _now(), "rationale": str(rationale)[:300] or None}
        if external_actor:
            stamp["external_actor"] = external_actor
        with self._lock:
            if approved and self._active is not None:
                raise Busy(self._active)
            rec["approval"] = {**rec["approval"], **stamp}
            if approved:
                rec.update(state="running", started=_now())
                self._active = run_id
            else:
                rec.update(state="refused", finished=_now(), note="the approval was rejected")
            self._write_status(run_id, rec)
        self.event(run_id, "run.approved" if approved else "run.rejected", f"{'approved' if approved else 'rejected'} by {user}", actor_user=user, via=via)
        if approved:
            self._launch(run_id, rec["profile"], rec["defect"])
        return rec

    def cancel(self, run_id: str, user: str) -> Dict[str, Any]:
        rec = self.get(run_id)
        if rec["state"] in TERMINAL:
            raise Refused("conflict", "the run has ended", status=409)
        if rec["state"] == "running":
            self._cancelled.add(run_id)
            proc = self._procs.get(run_id)
            if proc is not None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
            return rec               # the runner thread records the end and the event
        rec.update(state="cancelled", finished=_now(), note=f"cancelled by {user} before it started")
        self._write_status(run_id, rec)
        self.event(run_id, "run.cancelled", f"cancelled by {user}")
        return rec

    def _launch(self, run_id: str, profile: str, defect: str) -> None:
        self.event(run_id, "run.started", "the redevops-qa command was started")
        threading.Thread(target=self._run, args=(run_id, profile, defect), name="run-" + run_id, daemon=True).start()

    def _argv(self, run_id: str, profile: str, defect: str) -> List[str]:
        p = catalog.PROFILES[profile]
        command, plan_file, _ = PLANS[p["plan"]]
        d = self.root / run_id
        argv = [self.cfg.cli, command]
        if plan_file is not None:
            argv.append(str(self.cfg.plans_dir / plan_file))
        return argv + ["--out", str(d / "evidence"), "--run-id", run_id, "--defect", defect]

    def _external_argv(self, run_id: str, origin: str) -> List[str]:
        """The command of a run against a registered external target: the plan is built here from the shipped example and the REGISTERED origin, written into the run's directory and given to ``run``."""
        d = self.root / run_id
        plan = catalog.edge_sentinel_plan(origin, self.cfg.plans_dir)
        (d / "plan.json").write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
        return [self.cfg.cli, "run", str(d / "plan.json"), "--out", str(d / "evidence"), "--run-id", run_id]

    def child_env(self, home: Path) -> Dict[str, str]:
        """The environment of the command: no variable of the service (the token is one) is passed on."""
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        for key in ("TMPDIR", "REDEVOPS_QA_PINS", "PLAYWRIGHT_BROWSERS_PATH"):
            if key in os.environ:
                env[key] = os.environ[key]
        return env

    def _run(self, run_id: str, profile: str, defect: str) -> None:
        d = self.root / run_id
        record = self.get(run_id)
        exit_code: Optional[int] = None
        try:
            home = d / "home"
            home.mkdir()
            with open(d / "output.txt", "wb") as out:
                target = self.targets.get(record["target_id"]) or {}
                argv = self._external_argv(run_id, target["origin"]) if target.get("kind") == "external-origin" else self._argv(run_id, profile, defect)
                proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT, cwd=str(d), env=self.child_env(home), start_new_session=True)
                self._procs[run_id] = proc
                try:
                    exit_code = proc.wait(timeout=self.cfg.run_timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                    record["note"] = f"killed after {self.cfg.run_timeout} seconds (QA_SERVICE_RUN_TIMEOUT)"
                    exit_code = None
                    record["state"] = "timed_out"
            if run_id in self._cancelled:
                record.update(state="cancelled", note="cancelled by an operator")
                exit_code = None
            elif record["state"] != "timed_out":
                record["state"] = "finished"
        except OSError as exc:
            record["state"] = "failed_to_start"
            record["note"] = f"the command could not be started ({type(exc).__name__})"
        self._procs.pop(run_id, None)
        shutil.rmtree(d / "home", ignore_errors=True)
        outcome = caps_outcome(exit_code)
        record.update(finished=_now(), exit_code=exit_code, outcome=outcome, level=level_for(outcome, record["level_ceiling"]))
        bundle = self.bundle_dir(run_id)
        record["bundle"] = bundle.name if bundle else None
        self._write_status(run_id, record)
        self.event(run_id, {"cancelled": "run.cancelled", "timed_out": "run.finished", "finished": "run.finished"}.get(record["state"], "run.finished"),
                   f"{record['state']}" + (f": {outcome}" if outcome else ""), state=record["state"], outcome=outcome, exit_code=exit_code)
        with self._lock:
            self._active = None

    # ------------------------------------------------------------------ reading a run
    def bundle_dir(self, run_id: str) -> Optional[Path]:
        ev = self._dir(run_id) / "evidence"
        try:
            kids = [p for p in ev.iterdir() if p.is_dir() and not p.is_symlink()]
        except OSError:
            return None
        return kids[0] if len(kids) == 1 else None

    def output(self, run_id: str) -> bytes:
        try:
            with open(self._dir(run_id) / "output.txt", "rb") as fh:
                return fh.read(OUTPUT_LIMIT)
        except OSError:
            return b""

    def uses_target(self, target_id: str) -> bool:
        return any(r.get("target_id") == target_id for r in self.list(10000)["items"])

    def delete(self, run_id: str) -> None:
        rec = self.get(run_id)
        if rec.get("state") == "running":
            raise Busy(run_id)
        shutil.rmtree(self._dir(run_id))

    def command(self, argv_tail: List[str], timeout: int = 130) -> Tuple[int, bytes]:
        """Run a read-only subcommand (``report``, ``verify``, ``inspect``) of the same command in a scratch home."""
        scratch = self.cfg.data_dir / "tmp"
        scratch.mkdir(parents=True, exist_ok=True)
        home = Path(os.environ.get("TMPDIR") or scratch)
        try:
            done = subprocess.run([self.cfg.cli] + argv_tail, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, env=self.child_env(home), cwd=str(scratch), check=False)
        except subprocess.TimeoutExpired:
            return 124, b""
        return done.returncode, done.stdout


def caps_outcome(exit_code: Optional[int]) -> Optional[str]:
    return EXIT_MEANING.get(exit_code) if exit_code is not None else None


def wait_idle(store: RunStore, seconds: float = 30.0) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if store._active is None:
            return True
        time.sleep(0.05)
    return False
