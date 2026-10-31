# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``PlaywrightAdapter``: the ``qa-adapter/1`` browser adapter, written over the :class:`~qa_playwright.driver.BrowserDriver`
protocol.

What this module guarantees (each point has offline tests against the fake driver):

* **One fresh, ephemeral context per session.** ``open_session`` asks the driver for a new context built from a
  :class:`~qa_playwright.driver.ContextSpec`, which has no field for stored state or a profile directory. ``reset`` gives a
  new context; ``close_session`` reports what was released and what leaked.
* **Page content is data, never an instruction.** This module holds no reference to a policy, a spec, an assertion set or a
  verifier, and nothing read from a page is put in an exception message, a detail string or a decision input: every
  error text is fixed and its ``details`` hold only closed-vocabulary values. Page-derived strings leave only inside the
  returned records and stored artifacts, after the redaction hook.
* **Redaction before anything leaves.** Every URL, name, text value, DOM metadata item, snapshot, excerpt and image goes
  through the injected ``Redactor`` first; only the redacted bytes reach the ``BlobSink``. A redactor that refuses, fails
  or returns something unusable is a ``RedactionFailed`` and the artifact is dropped. An input over the raw bound is
  refused whole (``ResourceLimitExceeded``), never cut before redaction.
* **Locators never guess.** ``locate`` returns every candidate with role, name, visibility, enabled state and a uniqueness
  flag. ``act`` takes the candidate ``locate`` produced, checks it again immediately before acting and refuses a target
  that is gone (``LocatorNotFound``) or no longer unique (``LocatorAmbiguous``).
* **Every action carries a policy decision reference** (``ActionBlockedByPolicy`` before the driver is touched
  otherwise), is auto-waited against the injected clock, and leaves an :class:`ActionReceiptPayload`.
* **``assert_`` reads and reports; it does not judge.** It takes a subject only. There is no expected value anywhere in
  this module and the return type has no verdict.
* **Deterministic time.** Every wait is a bounded poll against the injected ``Clock``; the driver only sleeps.
"""
from __future__ import annotations

import json
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

import unicodedata

from . import _harness as h
from ._harness import (ABOUT_BLANK, ActionBlockedByPolicy, ActionKind, ActionOutcome, ActionRequest, ActionTimeout,
                       AdapterCrash, AssertionSubject, BlobSink, BrowserCrash, CaptureKind, CleanupReport, Clock,
                       EgressGuard, EnvironmentUnhealthy, EvidenceRef, LocateCandidate, LocateMode, LocateResult,
                       LocatorAmbiguous, LocatorDescriptor, LocatorNotFound, NavigationDenied, Observation,
                       ObservationSource, ObservedValue, ObserveRequest, Phase, QAAdapterError, RedactionFailed, Redactor,
                       ResetFailed, ResetResult, ResetScope, Resolution, ResolvedTarget, ResourceLimitExceeded,
                       ResultCode, SecretRef, SessionHandle, SessionLost, SessionProfile, SubjectKind,
                       TargetNotActionable, UnexpectedDialog, UnsupportedOperation)
from .config import AdapterConfig, EgressProfile
from .driver import (PERFORM_KINDS, BrowserDriver, ContextSpec, DriverFault, DriverSession, ElementInfo, ElementQuery,
                     EventLog, FaultKind, RequestInfo)
from .payload import ActionReceiptPayload

QAError = h.errors.QAError
ADAPTER_ID = "qa-playwright"
ADAPTER_VERSION = "0.1.0.dev0"
API_VERSION = "qa-adapter/1"
FRAME_MAIN = "main"
#: roles of a covering element that mean "a dialog got in the way" (UnexpectedDialog) rather than "the target is blocked"
DIALOG_ROLES = frozenset({"dialog", "alertdialog"})
_RCV1 = re.compile(r"rcv1:[0-9a-f]{64}")
_SENSITIVE_MARK = "[withheld:sensitive]"
_OVERSIZE_MARK = "[withheld:oversize]"
_DESTRUCTIVE_KINDS = frozenset(PERFORM_KINDS)


def _norm_text(text: str) -> str:
    """Whitespace-normalised rendered text: runs of whitespace become one space, the ends are trimmed."""
    return " ".join(text.split())


@dataclass
class _Cand:
    driver_ref: str
    query: ElementQuery
    descriptor_hash: str


@dataclass
class _Session:
    n: int
    session_id: str
    spec: ContextSpec
    profile: EgressProfile
    guard: EgressGuard
    ds: Optional[DriverSession] = None
    lost: bool = False
    report: Optional[CleanupReport] = None
    cand_seq: int = 0
    obs_seq: int = 0
    cands: "OrderedDict[str, _Cand]" = field(default_factory=OrderedDict)
    payloads: List[ActionReceiptPayload] = field(default_factory=list)


class PlaywrightAdapter:
    """The browser adapter. Satisfies the structural ``QAAdapter`` protocol (contracts form and neutral form)."""

    adapter_id: str = ADAPTER_ID
    adapter_version: str = ADAPTER_VERSION
    api_version: str = API_VERSION

    def __init__(self, driver: BrowserDriver, *, blobs: BlobSink, redactor: Redactor, clock: Clock,
                 egress_profiles: Mapping[str, EgressProfile], config: Optional[AdapterConfig] = None,
                 secret_resolver: Optional[Callable[[SecretRef], str]] = None,
                 decision_check: Optional[Callable[[str], bool]] = None,
                 fixture_resetter: Optional[Callable[[str], bool]] = None) -> None:
        for name, value, methods in (("driver", driver, ("new_session", "close")), ("blobs", blobs, ("put", "get")),
                                     ("redactor", redactor, ("redact",)), ("clock", clock, ("now_utc", "monotonic_ms"))):
            if any(not callable(getattr(value, m, None)) for m in methods):
                raise TypeError(f"PlaywrightAdapter: {name} does not provide {', '.join(methods)}")
        if not isinstance(getattr(redactor, "policy_id", None), str):
            raise TypeError("PlaywrightAdapter: the redactor has no policy_id")
        if any(type(p) is not EgressProfile or p.profile_id != k for k, p in egress_profiles.items()):
            raise TypeError("PlaywrightAdapter: egress_profiles maps a profile id to its EgressProfile")
        self._driver = driver
        self._blobs = blobs
        self._redactor = redactor
        self._clock = clock
        self._profiles: Dict[str, EgressProfile] = dict(egress_profiles)
        self._cfg = config if config is not None else AdapterConfig()
        self._secrets = secret_resolver
        self._decision_check = decision_check
        self._fixture_resetter = fixture_resetter
        self._sessions: Dict[str, _Session] = {}
        self._counter = 0

    # ------------------------------------------------------------------------------------------------------------
    # shared plumbing
    # ------------------------------------------------------------------------------------------------------------

    def _session(self, s: Any, *, closing: bool = False) -> _Session:
        if type(s) is not SessionHandle:
            raise UnsupportedOperation("the session handle is not a SessionHandle")
        sess = self._sessions.get(s.session_id)
        if sess is None:
            raise SessionLost("no such session")
        if sess.report is not None:
            if closing:
                return sess
            raise SessionLost("the session is closed")
        if not closing and (sess.lost or (sess.ds is not None and sess.ds.is_closed())):
            sess.lost = True
            raise SessionLost("the browser session is gone")
        return sess

    def _map_fault(self, sess: _Session, fault: DriverFault) -> QAAdapterError:
        kind = fault.kind
        if kind is FaultKind.SESSION_CLOSED:
            sess.lost = True
            return SessionLost("the browser session was closed")
        if kind is FaultKind.CRASHED:
            sess.lost = True
            return BrowserCrash("the browser or the page crashed")
        if kind is FaultKind.TIMEOUT:
            return ActionTimeout("the browser did not finish in time")
        if kind is FaultKind.DETACHED:
            return LocatorNotFound("the element is no longer attached")
        if kind is FaultKind.OBSCURED:
            if fault.obscurer_role in DIALOG_ROLES:
                return UnexpectedDialog("a dialog covers the target")
            return TargetNotActionable("the target is covered", reason="obscured")
        if kind in (FaultKind.NOT_VISIBLE, FaultKind.DISABLED, FaultKind.NOT_EDITABLE):
            return TargetNotActionable("the target cannot be acted on", reason=kind.value.lower())
        if kind is FaultKind.NAVIGATION_BLOCKED:
            return NavigationDenied("the egress policy does not allow this navigation")
        if kind is FaultKind.DIALOG:
            return UnexpectedDialog("a dialog interrupted the operation")
        if kind is FaultKind.LIMIT:
            return ResourceLimitExceeded("a browser-side bound was hit")
        if kind is FaultKind.INVALID:
            return UnsupportedOperation("the browser cannot do this")
        return AdapterCrash("the browser driver failed", cause="OTHER")

    def _drv(self, sess: _Session, fn: Callable[..., Any], *args: Any) -> Any:
        """Call the driver. Typed errors pass; a driver fault is mapped to its harness error; anything else is an
        ``AdapterCrash`` that names only the exception class (an exception text could echo page content)."""
        try:
            return fn(*args)
        except QAError:
            raise
        except DriverFault as fault:
            raise self._map_fault(sess, fault) from None
        except Exception as exc:
            raise AdapterCrash("the browser driver failed", cause=type(exc).__name__) from None

    def _poll(self, sess: _Session, probe: Callable[[], Any], timeout_ms: int) -> Any:
        """``probe()`` until it returns something truthy or ``timeout_ms`` of the injected clock have passed. Bounded by
        an iteration count as well, so a clock that never advances cannot make this loop forever."""
        poll = self._cfg.poll_interval_ms
        deadline = self._clock.monotonic_ms() + timeout_ms
        value = probe()
        for _ in range(timeout_ms // poll + 2):
            remaining = deadline - self._clock.monotonic_ms()
            if value or remaining <= 0:
                break
            self._drv(sess, sess.ds.settle, min(poll, remaining))
            value = probe()
        return value

    # -- redaction ------------------------------------------------------------------------------------------------
    def _redact_bytes(self, data: bytes, media: str, cap: int) -> bytes:
        if len(data) > cap:
            raise ResourceLimitExceeded("an artifact is over the raw size bound", bound="raw")
        try:
            out = self._redactor.redact(bytes(data), media)
        except QAError:
            raise
        except Exception as exc:
            raise RedactionFailed("the redaction hook failed", cause=type(exc).__name__) from None
        if type(out) is not bytes:
            raise RedactionFailed("the redaction hook returned something that is not bytes")
        return out

    def _redact_text(self, text: str, media: str = "text/plain", cap: Optional[int] = None) -> str:
        raw = unicodedata.normalize("NFC", text).encode("utf-8", errors="replace")
        out = self._redact_bytes(raw, media, cap if cap is not None else self._cfg.max_raw_text_bytes)
        try:
            return out.decode("utf-8")
        except UnicodeDecodeError:
            raise RedactionFailed("the redaction hook returned text that is not UTF-8") from None

    def _redact_json(self, value: Any) -> Tuple[Any, bool]:
        """Redact a JSON value through the hook (as ``application/json``); returns the redacted value and whether the hook
        changed it."""
        raw = unicodedata.normalize("NFC", json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        out = self._redact_text(raw, "application/json", self._cfg.max_raw_artifact_bytes)
        try:
            back = json.loads(out)
        except ValueError:
            raise RedactionFailed("the redaction hook returned JSON that does not parse") from None
        return back, json.dumps(back, sort_keys=True, separators=(",", ":"), ensure_ascii=False) != raw

    def _bounded(self, text: str, limit: int) -> str:
        """Cut AFTER redaction (a cut before could separate a key from its value)."""
        return text if len(text) <= limit else text[:limit - 1] + "\u2026"

    def _evidence(self, data: bytes, media: str, modality: str, *, store: bool) -> EvidenceRef:
        if store:
            try:
                digest = self._blobs.put(data, media)
            except QAError:
                raise
            except Exception as exc:
                raise ResourceLimitExceeded("the blob sink refused the artifact", cause=type(exc).__name__) from None
        else:
            digest = h.digest_of_bytes(data)
        return h.evidence_ref(digest, media, modality=modality)

    # -- observation building --------------------------------------------------------------------------------------
    def _excerpt_doc(self, log: EventLog, render: Callable[[Any], Dict[str, Any]]) -> Dict[str, Any]:
        cap = self._cfg.max_excerpt_entries
        events = tuple(log.events)
        dropped = log.dropped + max(0, len(events) - cap)
        return {"dropped": dropped, "entries": [render(e) for e in events[-cap:]]}

    def _console_entry(self, e: Any) -> Dict[str, Any]:
        text = self._redact_text(str(e.text))
        return {"level": str(e.level)[:16], "text": self._bounded(text, self._cfg.max_excerpt_text_chars)}

    def _network_entry(self, e: Any) -> Dict[str, Any]:
        url = self._redact_text(str(e.url))
        return {"blocked": bool(e.blocked), "failed": bool(e.failed), "method": str(e.method)[:16],
                "resource_type": str(e.resource_type)[:32], "status": e.status if type(e.status) is int else None,
                "url": self._bounded(url, 512)}

    def _dom_meta(self, sess: _Session) -> Dict[str, Any]:
        meta = self._drv(sess, sess.ds.page_meta)
        title = self._bounded(self._redact_text(str(meta.title)), self._cfg.max_title_chars)
        doc = {"elements": int(meta.elements), "forms": int(meta.forms), "inputs": int(meta.inputs),
               "lang": str(meta.lang)[:35], "links": int(meta.links), "ready_state": str(meta.ready_state)[:16],
               "title": title}
        doc, _ = self._redact_json(doc)
        if len(json.dumps(doc, ensure_ascii=False).encode("utf-8")) > 4096:
            doc.pop("title", None)
        return doc

    def _build_observation(self, sess: _Session, *, step_id: str, phase: Phase, kinds: Sequence[CaptureKind],
                           store: bool) -> Observation:
        started = self._clock.monotonic_ms()
        wanted = set(kinds)
        sess.obs_seq += 1
        url = self._bounded(self._redact_text(self._drv(sess, sess.ds.current_url)), 2048) or ABOUT_BLANK
        refs: Dict[str, Any] = {}
        if CaptureKind.DOM_META in wanted:
            refs["dom_meta"] = self._dom_meta(sess)
        if CaptureKind.A11Y_SNAPSHOT in wanted:
            text = self._drv(sess, sess.ds.accessibility_snapshot)
            out = self._redact_bytes(str(text).encode("utf-8", errors="replace"), "text/plain",
                                     self._cfg.max_raw_artifact_bytes)
            refs["a11y_snapshot_ref"] = self._evidence(out, "text/plain", "text", store=store)
        if CaptureKind.SCREENSHOT in wanted:
            png = self._drv(sess, sess.ds.screenshot)
            out = self._redact_bytes(bytes(png), "image/png", self._cfg.max_raw_artifact_bytes)
            refs["screenshot_ref"] = self._evidence(out, "image/png", "image", store=store)
        if CaptureKind.CONSOLE_EXCERPT in wanted:
            doc, _ = self._redact_json(self._excerpt_doc(self._drv(sess, sess.ds.console_log), self._console_entry))
            refs["console_excerpt_ref"] = self._evidence(
                json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8"), "application/json", "text",
                store=store)
        if CaptureKind.NETWORK_EXCERPT in wanted:
            doc, _ = self._redact_json(self._excerpt_doc(self._drv(sess, sess.ds.network_log), self._network_entry))
            refs["network_excerpt_ref"] = self._evidence(
                json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8"), "application/json", "text",
                store=store)
        driver = self._driver
        return Observation(
            observation_id=h.bounded_id("obs", sess.session_id, sess.obs_seq), step_id=step_id, phase=phase,
            source=ObservationSource(adapter=self.adapter_id, adapter_version=self.adapter_version,
                                     browser=str(driver.browser_name)[:512], browser_version=str(driver.browser_version)[:512]),
            redaction_applied=True, redaction_policy_id=self._redactor.policy_id, url=url, frame=FRAME_MAIN,
            duration_ms=max(0, self._clock.monotonic_ms() - started), observed_at=self._clock.now_utc(), **refs)

    def _state_hash(self, sess: _Session) -> str:
        """The harness state hash of the page as ``observe`` would show it, without storing any artifact."""
        obs = self._build_observation(sess, step_id="state", phase=Phase.BEFORE, kinds=self._cfg.default_capture,
                                      store=False)
        return h.state_hash(obs)

    # ------------------------------------------------------------------------------------------------------------
    # open_session / close_session / reset
    # ------------------------------------------------------------------------------------------------------------

    def _gate(self, sess: _Session) -> Callable[[RequestInfo], bool]:
        def gate(info: RequestInfo) -> bool:
            try:
                url = info.url
                if url == ABOUT_BLANK:
                    return True
                if not info.is_navigation and url[:5].lower() == "data:":
                    return True           # inline data is not network traffic; it cannot be a navigation
                return sess.guard.check(url, purpose="navigation" if info.is_navigation else "subresource").allowed
            except Exception:             # fail closed on anything unexpected
                return False
        return gate

    def open_session(self, profile: SessionProfile) -> SessionHandle:
        if type(profile) is not SessionProfile:
            raise UnsupportedOperation("open_session takes a SessionProfile")
        if profile.redaction_policy_id != self._redactor.policy_id:
            raise RedactionFailed("the session names a redaction policy other than the one this adapter applies")
        egress = self._profiles.get(profile.egress_profile)
        if egress is None:
            raise UnsupportedOperation("the egress profile is not configured on this adapter")
        self._counter += 1
        session_id = f"sess-{self._counter}"
        sess = _Session(n=self._counter, session_id=session_id, spec=None, profile=egress,  # type: ignore[arg-type]
                        guard=EgressGuard(egress.policy, egress.resolver))
        spec = ContextSpec(
            session_id=session_id, profile_id=egress.profile_id, launch_args=tuple(egress.launch_args), proxy=egress.proxy,
            accept_downloads=profile.allow_downloads, allow_popups=profile.allow_popups,
            allow_file_choosers=profile.allow_file_choosers, service_workers="block", permissions=(),
            record_trace=self._cfg.allow_trace, request_gate=self._gate(sess))
        sess.spec = spec
        try:
            sess.ds = self._driver.new_session(spec)
        except QAError:
            raise
        except DriverFault as fault:
            raise self._map_fault(sess, fault) from None
        except Exception as exc:
            raise AdapterCrash("the browser session could not be opened", cause=type(exc).__name__) from None
        self._sessions[session_id] = sess
        return SessionHandle(session_id=session_id)

    def close_session(self, s: SessionHandle) -> CleanupReport:
        sess = self._session(s, closing=True)
        if sess.report is not None:
            return sess.report
        leaked: Tuple[str, ...] = ()
        released: Tuple[str, ...] = ()
        try:
            rep = sess.ds.close()
            released, leaked = tuple(rep.released), tuple(rep.leaked)
            if not sess.ds.is_closed():
                leaked = tuple(sorted(set(leaked) | {"context"}))
        except Exception:
            leaked = ("context",)
        sess.cands.clear()
        sess.report = CleanupReport(handle_id=sess.session_id, verified=not leaked, leaked=leaked, released=released,
                                    closed_at=self._clock.now_utc())
        return sess.report

    def reset(self, s: SessionHandle, scope: ResetScope) -> ResetResult:
        sess = self._session(s)
        if type(scope) is not ResetScope:
            raise UnsupportedOperation("reset takes a ResetScope")
        if scope is not ResetScope.CONTEXT and self._fixture_resetter is None:
            raise UnsupportedOperation("this adapter resets the browser context only")
        try:
            sess.ds.reset()
        except Exception:
            sess.lost = True
            raise ResetFailed("the browser context could not be reset") from None
        sess.cands.clear()
        if scope is not ResetScope.CONTEXT:
            try:
                ok = self._fixture_resetter(scope.value)
            except Exception:
                ok = False
            if ok is not True:
                raise ResetFailed("the fixture or environment could not be reset")
        return ResetResult(ok=True, scope=scope)

    def shutdown(self) -> None:
        """Close every session still open and the driver. Not part of the protocol."""
        for sess in list(self._sessions.values()):
            if sess.report is None:
                self.close_session(SessionHandle(session_id=sess.session_id))
        self._driver.close()

    # ------------------------------------------------------------------------------------------------------------
    # observe / capture
    # ------------------------------------------------------------------------------------------------------------

    def observe(self, s: SessionHandle, req: ObserveRequest) -> Observation:
        sess = self._session(s)
        if type(req) is not ObserveRequest:
            raise UnsupportedOperation("observe takes an ObserveRequest")
        kinds = tuple(req.capture) or self._cfg.default_capture
        if CaptureKind.TRACE in kinds:
            raise UnsupportedOperation("a trace is captured with capture(), not observed")
        return self._build_observation(sess, step_id=req.step_id, phase=req.phase, kinds=kinds, store=True)

    def capture(self, s: SessionHandle, kinds: Sequence[CaptureKind]) -> Sequence[EvidenceRef]:
        sess = self._session(s)
        out: List[EvidenceRef] = []
        seen = set()
        for kind in kinds:
            if type(kind) is not CaptureKind:
                raise UnsupportedOperation("capture takes CaptureKind values")
            if kind in seen:
                continue
            seen.add(kind)
            if kind is CaptureKind.TRACE:
                out.append(self._capture_trace(sess))
                continue
            if kind is CaptureKind.DOM_META:
                doc = self._dom_meta(sess)
                data = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
                out.append(self._evidence(self._redact_bytes(data, "application/json", self._cfg.max_raw_artifact_bytes),
                                          "application/json", "text", store=True))
                continue
            obs = self._build_observation(sess, step_id="capture", phase=Phase.AFTER, kinds=(kind,), store=True)
            ref = {CaptureKind.A11Y_SNAPSHOT: obs.a11y_snapshot_ref, CaptureKind.SCREENSHOT: obs.screenshot_ref,
                   CaptureKind.CONSOLE_EXCERPT: obs.console_excerpt_ref,
                   CaptureKind.NETWORK_EXCERPT: obs.network_excerpt_ref}[kind]
            out.append(ref)
        return tuple(out)

    def _capture_trace(self, sess: _Session) -> EvidenceRef:
        if not self._cfg.allow_trace:
            raise UnsupportedOperation("traces are disabled for this adapter")
        data = self._drv(sess, sess.ds.export_trace)
        redacted = self._redact_bytes(bytes(data), self._cfg.trace_media_type, self._cfg.max_raw_artifact_bytes * 25)
        ref = self._evidence(redacted, self._cfg.trace_media_type, "other", store=True)
        return EvidenceRef(ref=ref.ref, content_hash=ref.content_hash, media_type=ref.media_type, modality=ref.modality,
                           source="restricted-trace")

    # ------------------------------------------------------------------------------------------------------------
    # locate
    # ------------------------------------------------------------------------------------------------------------

    @staticmethod
    def _query(target: LocatorDescriptor, mode: LocateMode) -> ElementQuery:
        exact = mode is LocateMode.EXACT
        hint = None if exact else target.text_hint
        if all(v is None for v in (target.role, target.name, target.label, target.test_id, hint)):
            raise UnsupportedOperation("a locator needs at least one of role, name, label or test id")
        return ElementQuery(role=target.role, name=target.name, label=target.label, test_id=target.test_id,
                            text_hint=hint, frame_path=tuple(target.frame_path), exact=exact)

    def locate(self, s: SessionHandle, target: LocatorDescriptor, *, mode: LocateMode) -> LocateResult:
        sess = self._session(s)
        if type(target) is not LocatorDescriptor or type(mode) is not LocateMode:
            raise UnsupportedOperation("locate takes a LocatorDescriptor and a LocateMode")
        query = self._query(target, mode)
        infos = tuple(self._poll(sess, lambda: tuple(self._drv(sess, sess.ds.query, query)), self._cfg.locate_timeout_ms))
        unique = len(infos) == 1
        descriptor_hash = h.canon.canon_hash(target.canonical_form())
        out: List[LocateCandidate] = []
        for info in infos[:self._cfg.max_candidates]:
            sess.cand_seq += 1
            ref = f"cand-{sess.n}-{sess.cand_seq}"
            sess.cands[ref] = _Cand(driver_ref=info.ref, query=query, descriptor_hash=descriptor_hash)
            while len(sess.cands) > self._cfg.max_candidate_table:
                sess.cands.popitem(last=False)
            out.append(LocateCandidate(
                candidate_ref=ref, enabled=bool(info.enabled), unique=unique, visible=bool(info.visible),
                name=self._bounded(self._redact_text(str(info.name)), 512), role=str(info.role)[:512]))
        return LocateResult(candidates=tuple(out))

    # ------------------------------------------------------------------------------------------------------------
    # act
    # ------------------------------------------------------------------------------------------------------------

    def _require_decision(self, action: Any) -> None:
        if type(action) is not ActionRequest:
            raise ActionBlockedByPolicy("act takes an ActionRequest that carries a policy decision reference")
        ref = action.policy_decision_ref
        if type(ref) is not str or _RCV1.fullmatch(ref) is None:
            raise ActionBlockedByPolicy("the action has no policy decision reference")
        if self._decision_check is not None:
            try:
                accepted = self._decision_check(ref)
            except Exception:
                accepted = False
            if accepted is not True:
                raise ActionBlockedByPolicy("the policy decision reference was not accepted")

    def _action_value(self, action: ActionRequest) -> Optional[str]:
        inner = action.action
        if inner.secret_ref is not None:
            if self._secrets is None:
                raise UnsupportedOperation("this adapter has no secret resolver")
            try:
                value = self._secrets(inner.secret_ref)
            except Exception:
                raise EnvironmentUnhealthy("the secret could not be resolved") from None
            if type(value) is not str:
                raise EnvironmentUnhealthy("the secret could not be resolved")
            return value
        return inner.value

    def _verify_target(self, sess: _Session, target: Any) -> _Cand:
        if type(target) is not ResolvedTarget:
            raise UnsupportedOperation("act takes the ResolvedTarget that locate produced")
        cand = sess.cands.get(target.candidate_ref)
        if cand is None:
            raise LocatorNotFound("the target is not a candidate of this session (it may be stale)")
        if cand.descriptor_hash != h.canon.canon_hash(target.locator.canonical_form()):
            raise UnsupportedOperation("the target was not produced by the locator it names")
        return cand

    def _reverify(self, sess: _Session, cand: _Cand) -> None:
        refs = [i.ref for i in self._drv(sess, sess.ds.query, cand.query)]
        if cand.driver_ref not in refs:
            raise LocatorNotFound("the target no longer matches its locator")
        if len(refs) != 1:
            raise LocatorAmbiguous("the locator no longer resolves to exactly one element")

    @staticmethod
    def _problem(info: ElementInfo, kind: str) -> Optional[Tuple[str, Optional[str]]]:
        if not info.visible:
            return ("hidden", None)
        if not info.enabled:
            return ("disabled", None)
        if kind == "fill" and not info.editable:
            return ("not_editable", None)
        if info.obscured_by is not None:
            return ("obscured", info.obscured_by)
        return None

    def _await_actionable(self, sess: _Session, ref: str, kind: str, timeout_ms: int) -> None:
        last: List[Optional[Tuple[str, Optional[str]]]] = [("hidden", None)]

        def probe() -> bool:
            last[0] = self._problem(self._drv(sess, sess.ds.inspect, ref), kind)
            return last[0] is None
        if self._poll(sess, probe, timeout_ms):
            return
        why, role = last[0]
        if why == "obscured":
            if role in DIALOG_ROLES:
                raise UnexpectedDialog("a dialog covers the target")
            raise TargetNotActionable("the target is covered", reason="obscured")
        raise TargetNotActionable("the target cannot be acted on", reason=why)

    def act(self, s: SessionHandle, action: ActionRequest, target: ResolvedTarget) -> ActionOutcome:
        self._require_decision(action)                      # before the session, the driver or the page is touched
        sess = self._session(s)
        started = self._clock.monotonic_ms()
        kind = action.action.kind
        value_digest = h.action_value_digest(action.action)
        cand: Optional[_Cand] = None
        if kind is ActionKind.NAVIGATE:
            url = action.action.value
            if type(url) is not str or not url:
                raise UnsupportedOperation("a navigation needs a URL value")
            if not sess.guard.check(url, purpose="navigation").allowed:
                raise NavigationDenied("the egress policy does not allow this navigation")
            before = self._state_hash(sess)
            self._drv(sess, sess.ds.goto, url, self._cfg.navigation_timeout_ms)
        else:
            cand = self._verify_target(sess, target)
            if kind is ActionKind.RESOLVE:
                before = self._state_hash(sess)
                self._reverify(sess, cand)                  # resolution only: the page is not changed
            else:
                name = kind.value
                if name not in _DESTRUCTIVE_KINDS:
                    raise UnsupportedOperation("this action kind is not supported")
                value = self._action_value(action)
                if name in ("fill", "press", "select") and value is None:
                    raise UnsupportedOperation("this action needs a value")
                before = self._state_hash(sess)
                self._reverify(sess, cand)
                self._await_actionable(sess, cand.driver_ref, name, self._cfg.action_timeout_ms)
                self._reverify(sess, cand)                  # nothing moved while we waited
                deadline_left = max(1, self._cfg.action_timeout_ms - (self._clock.monotonic_ms() - started))
                self._drv(sess, sess.ds.perform, cand.driver_ref, name, value, deadline_left)
        after = self._state_hash(sess)
        sess.payloads.append(ActionReceiptPayload(
            session_id=sess.session_id, step_id=action.step_id, idempotency_key=action.idempotency_key,
            policy_decision_ref=action.policy_decision_ref, action_kind=kind.value, value_digest=value_digest,
            candidate_ref=target.candidate_ref if cand is not None else None,
            locator_used=target.locator if cand is not None else None,
            strategy=str(target.strategy) if cand is not None else None, state_before_hash=before,
            state_after_hash=after, result=ResultCode.OK.value,
            duration_ms=max(0, self._clock.monotonic_ms() - started)))
        return ActionOutcome(result=ResultCode.OK)

    def receipt_payloads(self, s: SessionHandle) -> Tuple[ActionReceiptPayload, ...]:
        """The payload of every action this session performed, in order. Not part of the protocol."""
        sess = self._sessions.get(s.session_id) if type(s) is SessionHandle else None
        if sess is None:
            raise SessionLost("no such session")
        return tuple(sess.payloads)

    def egress_decisions(self, s: SessionHandle) -> Tuple[Any, ...]:
        """Drain the egress decisions made for this session (records with a ``canon-v1`` hash, host only). Not part of the
        protocol; the runner's own egress guard is separate."""
        sess = self._sessions.get(s.session_id) if type(s) is SessionHandle else None
        if sess is None:
            raise SessionLost("no such session")
        return sess.guard.drain()

    def egress_counts(self, s: SessionHandle) -> Dict[str, Any]:
        sess = self._sessions.get(s.session_id) if type(s) is SessionHandle else None
        if sess is None:
            raise SessionLost("no such session")
        return {"counts": sess.guard.counts, "denied_hosts": [list(i) for i in sess.guard.denied_hosts()]}

    # ------------------------------------------------------------------------------------------------------------
    # assert_
    # ------------------------------------------------------------------------------------------------------------

    def _observed(self, resolution: Resolution, count: int, value: Any = None, digest: Optional[str] = None
                  ) -> ObservedValue:
        return ObservedValue(resolution=resolution, match_count=count, value=value, value_digest=digest)

    def _value_result(self, value: Any) -> ObservedValue:
        """A resolved value, redacted. If redaction changed it, or it is too long, only the digest of what is safe to
        keep is returned: the verifier then cannot compare (INDETERMINATE), and ``ABSENT`` cannot pass on it."""
        if type(value) is str and len(value) > self._cfg.max_value_chars:
            return self._observed(Resolution.RESOLVED, 1, None, h.json_value_digest(_OVERSIZE_MARK))
        redacted, changed = self._redact_json(value)
        if changed:
            return self._observed(Resolution.RESOLVED, 1, None, h.json_value_digest(redacted))
        return self._observed(Resolution.RESOLVED, 1, redacted, h.json_value_digest(redacted))

    def assert_(self, s: SessionHandle, subject: AssertionSubject) -> ObservedValue:
        sess = self._session(s)
        if type(subject) is not AssertionSubject:
            raise UnsupportedOperation("assert_ takes an AssertionSubject")
        kind = subject.kind
        if kind is SubjectKind.UI_ELEMENT:
            return self._assert_element(sess, subject)
        if kind is SubjectKind.URL:
            return self._value_result(str(self._drv(sess, sess.ds.current_url)))
        if kind is SubjectKind.RESPONSE:
            return self._assert_response(sess, subject)
        raise UnsupportedOperation("this subject kind is not read by the browser adapter")

    def _visible(self, sess: _Session, query: ElementQuery) -> Tuple[ElementInfo, ...]:
        return tuple(i for i in self._drv(sess, sess.ds.query, query) if i.visible)

    def _assert_element(self, sess: _Session, subject: AssertionSubject) -> ObservedValue:
        if subject.locator is None:
            raise UnsupportedOperation("an element subject needs a locator")
        # the frozen descriptor first, then only the alternates listed in the hashed spec; never anything else
        for descriptor in (subject.locator, *subject.subject_alternates):
            query = self._query(descriptor, LocateMode.EXACT)
            infos = self._poll(sess, lambda: self._visible(sess, query), self._cfg.assert_timeout_ms)
            if len(infos) > 1:
                return self._observed(Resolution.AMBIGUOUS, len(infos))        # never "the first one"
            if len(infos) == 1:
                return self._read_element(sess, infos[0])
        return self._observed(Resolution.UNRESOLVED, 0)

    def _read_element(self, sess: _Session, info: ElementInfo) -> ObservedValue:
        reading = self._drv(sess, sess.ds.read, info.ref)
        if info.sensitive or reading.sensitive:
            return self._observed(Resolution.RESOLVED, 1, None, h.json_value_digest(_SENSITIVE_MARK))
        if reading.kind == "checked":
            if type(reading.checked) is not bool:
                return self._observed(Resolution.UNRESOLVED, 0)
            return self._value_result(reading.checked)
        text = str(reading.text)
        return self._value_result(text if reading.kind == "value" else _norm_text(text))

    def _assert_response(self, sess: _Session, subject: AssertionSubject) -> ObservedValue:
        if not subject.pattern:
            raise UnsupportedOperation("a response subject needs a pattern")
        try:
            pattern = re.compile(subject.pattern)
        except re.error:
            raise UnsupportedOperation("the response pattern is not a valid expression") from None
        log = self._drv(sess, sess.ds.network_log)
        if log.dropped:
            return self._observed(Resolution.UNRESOLVED, 0)                     # events were lost: nothing can be proven
        matches: "OrderedDict[Tuple[str, str], Any]" = OrderedDict()
        for e in log.events:
            if e.status is None or e.blocked or e.failed:
                continue
            bare = str(e.url).split("#", 1)[0].split("?", 1)[0]
            if pattern.search(bare) is not None:
                matches[(str(e.method), bare)] = e.status
        if not matches:
            return self._observed(Resolution.UNRESOLVED, 0)
        if len(matches) > 1:
            return self._observed(Resolution.AMBIGUOUS, len(matches))
        return self._value_result(int(next(iter(matches.values()))))
