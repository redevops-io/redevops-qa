# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Product-local typed models of the adapter protocol.

These models are local to this repository: they are not the frozen qa/v1 contracts and are not the harness neutral records.
Every model is immutable, validates on construction, rejects unknown fields on ``from_dict`` and round-trips through
``to_dict``. Strings are bounded, paths are relative where the model says so, and nothing here carries an oracle verdict:
``AdapterResult.authority`` is the constant ``"native"``.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from dataclasses import dataclass, field, fields
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from .errors import ModelError
from .status import AdapterClass, ErrorCode, Status

MANIFEST_SCHEMA = "redevops-qa/adapter-manifest/1"
RESULT_SCHEMA = "redevops-qa/adapter-result/1"

_SLUG = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MEDIA = re.compile(r"^[a-z]+/[a-z0-9.+-]+$")
_SELECTOR = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_ .:/*?\[\]@=-]{0,255}$")
_ACTION_KIND = re.compile(r"^[a-z][a-z_]{0,31}$")
_RELEASE = re.compile(r"^\d+(\.\d+)*([.-]?(a|b|rc|beta|dev)\d+)?$")

MAX_TEXT = 4096
MAX_ITEMS = 10_000

# What a suite adapter may never declare: it runs an existing suite and imports a native report; it is not steered mid-test.
STEERING_CAPABILITIES = frozenset({"steer", "mid_test_steering", "interactive", "act", "click", "type", "navigate", "inject", "pause", "resume"})


# ------------------------------------------------------------------------------------------------ helpers
def _text(name: str, value: Any, *, maxlen: int = MAX_TEXT, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise ModelError(f"{name} must be a string")
    if "\x00" in value:
        raise ModelError(f"{name} contains a NUL byte")
    if len(value) > maxlen:
        raise ModelError(f"{name} is longer than {maxlen} characters")
    if not allow_empty and not value:
        raise ModelError(f"{name} must not be empty")
    return value


def _match(name: str, value: Any, pattern: "re.Pattern[str]") -> str:
    _text(name, value, maxlen=256, allow_empty=False)
    if not pattern.match(value):
        raise ModelError(f"{name} has an invalid form")
    return value


def _num(name: str, value: Any, *, lo: float, hi: float, integer: bool = False) -> Any:
    if isinstance(value, bool) or not isinstance(value, (int,) if integer else (int, float)):
        raise ModelError(f"{name} must be {'an integer' if integer else 'a number'}")
    if value != value or not (lo <= value <= hi):       # NaN fails the comparison
        raise ModelError(f"{name} must be between {lo} and {hi}")
    return value


def _enum(name: str, enum_cls, value: Any):
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(value)
    except ValueError:
        raise ModelError(f"{name} is not one of {[e.value for e in enum_cls]}") from None


def _tuple(name: str, value: Any, item: Callable[[str, Any], Any], *, maxlen: int = MAX_ITEMS) -> tuple:
    if isinstance(value, (str, bytes, dict)) or not hasattr(value, "__iter__"):
        raise ModelError(f"{name} must be a list")
    items = tuple(value)
    if len(items) > maxlen:
        raise ModelError(f"{name} has more than {maxlen} items")
    return tuple(item(f"{name}[{i}]", v) for i, v in enumerate(items))


def _mapping(name: str, value: Any, key: Callable[[str, Any], str], val: Callable[[str, Any], Any], *, maxlen: int = 256) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ModelError(f"{name} must be a mapping")
    if len(value) > maxlen:
        raise ModelError(f"{name} has more than {maxlen} entries")
    return {key(f"{name} key", k): val(f"{name}[{k!r}]", v) for k, v in value.items()}


def _set(obj: Any, **values: Any) -> None:
    for k, v in values.items():
        object.__setattr__(obj, k, v)


def _from_dict(cls, data: Any, conv: Mapping[str, Callable[[Any], Any]]):
    if not isinstance(data, Mapping):
        raise ModelError(f"{cls.__name__} must be built from a mapping")
    known = {f.name for f in fields(cls)}
    unknown = set(data) - known
    if unknown:
        raise ModelError(f"{cls.__name__}: unknown field(s) {sorted(map(str, unknown))}")
    required = {f.name for f in fields(cls) if f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING}
    missing = required - set(data)
    if missing:
        raise ModelError(f"{cls.__name__}: missing field(s) {sorted(missing)}")
    return cls(**{k: conv.get(k, lambda v: v)(v) for k, v in data.items()})


def _plain(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, (Status, AdapterClass, ErrorCode)):
        return value.value
    if isinstance(value, (tuple, list)):
        return [_plain(v) for v in value]
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    return value


def canonical_json(data: Any) -> bytes:
    """Deterministic JSON (sorted keys, no floats beyond what ``json`` writes, UTF-8) used for digests."""
    return json.dumps(_plain(data), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(data: Any) -> str:
    return hashlib.sha256(canonical_json(data)).hexdigest()


# ------------------------------------------------------------------------------------------------ limits
@dataclass(frozen=True)
class Limits:
    """Supervisor limits. A request may ask for less than its manifest allows, never for more (see ``clamp``)."""

    deadline_s: float = 300.0
    output_limit_bytes: int = 1_000_000          # per stream: stdout and stderr each
    max_steps: int = 50                          # interactive: actions per session
    max_retries: int = 0                         # suite: whole-run retries; interactive: retries per action
    kill_grace_s: float = 2.0                    # between the terminate signal and the kill signal
    max_artifact_bytes: int = 50_000_000

    def __post_init__(self) -> None:
        _num("deadline_s", self.deadline_s, lo=0.05, hi=HARD_CAPS_RAW["deadline_s"])
        _num("output_limit_bytes", self.output_limit_bytes, lo=1, hi=HARD_CAPS_RAW["output_limit_bytes"], integer=True)
        _num("max_steps", self.max_steps, lo=1, hi=HARD_CAPS_RAW["max_steps"], integer=True)
        _num("max_retries", self.max_retries, lo=0, hi=HARD_CAPS_RAW["max_retries"], integer=True)
        _num("kill_grace_s", self.kill_grace_s, lo=0.0, hi=HARD_CAPS_RAW["kill_grace_s"])
        _num("max_artifact_bytes", self.max_artifact_bytes, lo=0, hi=HARD_CAPS_RAW["max_artifact_bytes"], integer=True)

    def clamp(self, ceiling: "Limits") -> "Limits":
        """Each value is the smaller of this and the ceiling; a request that asks for more is cut, not obeyed."""
        return Limits(**{f.name: min(getattr(self, f.name), getattr(ceiling, f.name)) for f in fields(self)})

    def exceeds(self, ceiling: "Limits") -> Tuple[str, ...]:
        return tuple(f.name for f in fields(self) if getattr(self, f.name) > getattr(ceiling, f.name))

    @classmethod
    def from_dict(cls, data: Any) -> "Limits":
        return _from_dict(cls, data, {})

    def to_dict(self) -> dict:
        return _plain(self)


HARD_CAPS_RAW = {"deadline_s": 3600.0, "output_limit_bytes": 16 * 1024 * 1024, "max_steps": 1000, "max_retries": 5,
                 "kill_grace_s": 30.0, "max_artifact_bytes": 1024 * 1024 * 1024}
HARD_CAPS = Limits(**HARD_CAPS_RAW)


# ------------------------------------------------------------------------------------------------ manifest
@dataclass(frozen=True)
class FrameworkRef:
    """The framework an adapter drives, tied to its entry in ``third_party/adapter-license-matrix.yaml``."""

    name: str
    pinned_release: str
    license_component: str

    def __post_init__(self) -> None:
        _text("framework.name", self.name, maxlen=64, allow_empty=False)
        _match("framework.pinned_release", self.pinned_release, _RELEASE)
        _match("framework.license_component", self.license_component, re.compile(r"^[a-z][a-z0-9-]{1,63}$"))

    @classmethod
    def from_dict(cls, data: Any) -> "FrameworkRef":
        return _from_dict(cls, data, {})


@dataclass(frozen=True)
class PinnedFile:
    path: str          # absolute path of an executable or a tool the adapter relies on
    sha256: str

    def __post_init__(self) -> None:
        _text("pinned_file.path", self.path, maxlen=1024, allow_empty=False)
        if not self.path.startswith("/"):
            raise ModelError("pinned_file.path must be absolute")
        _match("pinned_file.sha256", self.sha256, _SHA256)

    @classmethod
    def from_dict(cls, data: Any) -> "PinnedFile":
        return _from_dict(cls, data, {})


@dataclass(frozen=True)
class AdapterManifest:
    """Product-local description of an adapter. It is not a contract and is not part of the frozen qa/v1 surface."""

    adapter_id: str
    adapter_version: str
    adapter_class: AdapterClass
    framework: FrameworkRef
    capabilities: Tuple[str, ...]
    allowed_executables: Tuple[str, ...] = ()
    env_allowlist: Tuple[str, ...] = ()
    secret_env_allowlist: Tuple[str, ...] = ()
    pinned_files: Tuple[PinnedFile, ...] = ()
    limits: Limits = field(default_factory=Limits)
    report_formats: Tuple[str, ...] = ()
    downloads: bool = False                      # an adapter that downloads at run time cannot run sealed; it is refused there
    network: str = "none"                        # a declaration the worker is expected to enforce; the supervisor does not
    schema: str = MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        _set(self,
             adapter_id=_match("adapter_id", self.adapter_id, _SLUG),
             adapter_version=_match("adapter_version", self.adapter_version, _RELEASE),
             adapter_class=_enum("adapter_class", AdapterClass, self.adapter_class),
             capabilities=_tuple("capabilities", self.capabilities, lambda n, v: _match(n, v, _ACTION_KIND), maxlen=64),
             allowed_executables=_tuple("allowed_executables", self.allowed_executables,
                                        lambda n, v: _text(n, v, maxlen=1024, allow_empty=False), maxlen=16),
             env_allowlist=_tuple("env_allowlist", self.env_allowlist, lambda n, v: _match(n, v, _ENV_NAME), maxlen=64),
             secret_env_allowlist=_tuple("secret_env_allowlist", self.secret_env_allowlist, lambda n, v: _match(n, v, _ENV_NAME), maxlen=16),
             report_formats=_tuple("report_formats", self.report_formats, lambda n, v: _text(n, v, maxlen=32, allow_empty=False), maxlen=8))
        if self.schema != MANIFEST_SCHEMA:
            raise ModelError(f"schema must be {MANIFEST_SCHEMA}")
        if not isinstance(self.framework, FrameworkRef):
            raise ModelError("framework must be a FrameworkRef")
        if not isinstance(self.limits, Limits):
            raise ModelError("limits must be a Limits")
        if not all(isinstance(p, PinnedFile) for p in self.pinned_files):
            raise ModelError("pinned_files must be PinnedFile entries")
        if self.limits.exceeds(HARD_CAPS):
            raise ModelError("manifest limits exceed the hard caps")
        if not isinstance(self.downloads, bool):
            raise ModelError("downloads must be a boolean")
        if self.network not in ("none", "egress-gateway"):
            raise ModelError("network must be 'none' or 'egress-gateway'")
        if set(self.env_allowlist) & set(self.secret_env_allowlist):
            raise ModelError("a name cannot be both a plain and a secret environment variable")
        for exe in self.allowed_executables:
            if not exe.startswith("/"):
                raise ModelError("allowed_executables must be absolute paths")
        if self.adapter_class is AdapterClass.SUITE:
            bad = sorted(set(self.capabilities) & STEERING_CAPABILITIES)
            if bad or not self.capabilities:
                raise ModelError(f"a suite adapter runs an existing suite and imports its report; it cannot declare {bad or 'no capability'} "
                                 "(no mid-test steering)")
            if set(self.capabilities) - {"run_suite", "import_native_report"}:
                raise ModelError("a suite adapter's capabilities are run_suite and import_native_report only")

    @classmethod
    def from_dict(cls, data: Any) -> "AdapterManifest":
        return _from_dict(cls, data, {
            "framework": FrameworkRef.from_dict, "limits": Limits.from_dict, "adapter_class": lambda v: _enum("adapter_class", AdapterClass, v),
            "pinned_files": lambda v: _tuple("pinned_files", v, lambda n, x: PinnedFile.from_dict(x), maxlen=32)})

    def to_dict(self) -> dict:
        return _plain(self)


# ------------------------------------------------------------------------------------------------ requests
def _rel_path(name: str, value: Any) -> str:
    """A relative path that stays inside its base by construction (checked again against the real file system later)."""
    _text(name, value, maxlen=1024, allow_empty=False)
    if value.startswith("/") or "\\" in value or any(part in ("..", "") for part in value.split("/")):
        raise ModelError(f"{name} must be a relative path without '..', empty parts or backslashes")
    return value


def _abs_path(name: str, value: Any) -> str:
    _text(name, value, maxlen=1024, allow_empty=False)
    if not value.startswith("/") or "\\" in value or ".." in value.split("/"):
        raise ModelError(f"{name} must be an absolute path without '..'")
    return value


@dataclass(frozen=True)
class SuiteRunRequest:
    run_id: str
    adapter_id: str
    workspace: str                       # absolute; the suite lives here
    suite_path: str                      # relative to the workspace
    output_dir: str                      # absolute; the only place the run writes native reports and artifacts
    selectors: Tuple[str, ...] = ()      # test names or tags; never an option (no leading '-')
    env: Mapping[str, str] = field(default_factory=dict)
    secret_env: Mapping[str, str] = field(default_factory=dict)
    limits: Optional[Limits] = None
    sealed: bool = True                  # a sealed run starts nothing that downloads and checks the pinned files first
    required_assertions: Tuple[str, ...] = ()
    assertion_mapping: Mapping[str, str] = field(default_factory=dict)      # native id -> canonical assertion id (explicit only)
    schema: str = "redevops-qa/suite-run-request/1"

    def __post_init__(self) -> None:
        _set(self,
             run_id=_match("run_id", self.run_id, _ID), adapter_id=_match("adapter_id", self.adapter_id, _SLUG),
             workspace=_abs_path("workspace", self.workspace), suite_path=_rel_path("suite_path", self.suite_path),
             output_dir=_abs_path("output_dir", self.output_dir),
             selectors=_tuple("selectors", self.selectors, lambda n, v: _match(n, v, _SELECTOR), maxlen=256),
             env=_mapping("env", self.env, lambda n, k: _match(n, k, _ENV_NAME), lambda n, v: _text(n, v, maxlen=4096)),
             secret_env=_mapping("secret_env", self.secret_env, lambda n, k: _match(n, k, _ENV_NAME),
                                 lambda n, v: _text(n, v, maxlen=4096, allow_empty=False), maxlen=16),
             required_assertions=_tuple("required_assertions", self.required_assertions, lambda n, v: _match(n, v, _ID), maxlen=1000),
             assertion_mapping=_mapping("assertion_mapping", self.assertion_mapping, lambda n, k: _match(n, k, _ID),
                                        lambda n, v: _match(n, v, _ID), maxlen=1000))
        if self.limits is not None and not isinstance(self.limits, Limits):
            raise ModelError("limits must be a Limits")
        if not isinstance(self.sealed, bool):
            raise ModelError("sealed must be a boolean")
        if set(self.env) & set(self.secret_env):
            raise ModelError("a name cannot be both a plain and a secret environment variable")
        if len(set(self.required_assertions)) != len(self.required_assertions):
            raise ModelError("required_assertions has duplicates")

    @classmethod
    def from_dict(cls, data: Any) -> "SuiteRunRequest":
        return _from_dict(cls, data, {"limits": lambda v: None if v is None else Limits.from_dict(v)})

    def to_dict(self) -> dict:
        d = _plain(self)
        d["secret_env"] = {k: "[REDACTED]" for k in self.secret_env}      # a serialised request never carries a secret value
        return d


@dataclass(frozen=True)
class InteractiveActionRequest:
    """One bounded action in an interactive session."""

    session_id: str
    adapter_id: str
    step_index: int
    kind: str                            # one of the adapter's declared capabilities
    target: str = ""
    value: Optional[str] = None
    secret_value: Optional[str] = None   # redacted everywhere; never serialised
    timeout_s: float = 10.0
    assertion_id: Optional[str] = None   # the canonical assertion an assertion-like action (a check) declares itself evidence for
    schema: str = "redevops-qa/interactive-action-request/1"

    def __post_init__(self) -> None:
        _set(self, session_id=_match("session_id", self.session_id, _ID), adapter_id=_match("adapter_id", self.adapter_id, _SLUG),
             kind=_match("kind", self.kind, _ACTION_KIND), target=_text("target", self.target, maxlen=1024))
        _num("step_index", self.step_index, lo=0, hi=HARD_CAPS_RAW["max_steps"], integer=True)
        _num("timeout_s", self.timeout_s, lo=0.05, hi=HARD_CAPS_RAW["deadline_s"])
        if self.value is not None:
            _text("value", self.value, maxlen=MAX_TEXT)
        if self.secret_value is not None:
            _text("secret_value", self.secret_value, maxlen=MAX_TEXT, allow_empty=False)
        if self.value is not None and self.secret_value is not None:
            raise ModelError("an action carries a value or a secret value, not both")
        if self.assertion_id is not None:
            _match("assertion_id", self.assertion_id, _ID)

    @classmethod
    def from_dict(cls, data: Any) -> "InteractiveActionRequest":
        return _from_dict(cls, data, {})

    def to_dict(self) -> dict:
        d = _plain(self)
        d["secret_value"] = None if self.secret_value is None else "[REDACTED]"
        return d

    def __repr__(self) -> str:
        return (f"InteractiveActionRequest(session_id={self.session_id!r}, step_index={self.step_index}, kind={self.kind!r}, "
                f"target={self.target!r}, value={self.value!r}, secret_value={'[REDACTED]' if self.secret_value else None})")


# ------------------------------------------------------------------------------------------------ results
@dataclass(frozen=True)
class NativeAssertion:
    """One result as the framework reported it. ``declared_assertion_ids`` are the canonical assertion ids the test itself names
    (for example in a tag); a mapping to a canonical assertion is honoured only when it agrees with them."""

    native_id: str
    name: str
    status: Status
    message: str = ""
    duration_s: float = 0.0
    declared_assertion_ids: Tuple[str, ...] = ()
    source: str = ""

    def __post_init__(self) -> None:
        _set(self, native_id=_match("native_id", self.native_id, _ID), name=_text("name", self.name, maxlen=512),
             status=_enum("status", Status, self.status), message=_text("message", self.message, maxlen=MAX_TEXT),
             declared_assertion_ids=_tuple("declared_assertion_ids", self.declared_assertion_ids, lambda n, v: _match(n, v, _ID), maxlen=32),
             source=_text("source", self.source, maxlen=512))
        _num("duration_s", self.duration_s, lo=0.0, hi=1e7)
        if self.status is Status.UNVERIFIED:
            raise ModelError("a framework cannot report UNVERIFIED; that status is assigned by the mapping step")

    @classmethod
    def from_dict(cls, data: Any) -> "NativeAssertion":
        return _from_dict(cls, data, {"status": lambda v: _enum("status", Status, v)})

    def to_dict(self) -> dict:
        return _plain(self)


@dataclass(frozen=True)
class EvidenceArtifact:
    path: str            # relative to the run's output directory
    media_type: str
    sha256: str
    size_bytes: int
    role: str = "native-report"

    def __post_init__(self) -> None:
        _set(self, path=_rel_path("artifact.path", self.path), media_type=_match("artifact.media_type", self.media_type, _MEDIA),
             sha256=_match("artifact.sha256", self.sha256, _SHA256), role=_match("artifact.role", self.role, re.compile(r"^[a-z][a-z0-9-]{0,31}$")))
        _num("artifact.size_bytes", self.size_bytes, lo=0, hi=HARD_CAPS_RAW["max_artifact_bytes"], integer=True)

    @classmethod
    def from_dict(cls, data: Any) -> "EvidenceArtifact":
        return _from_dict(cls, data, {})

    def to_dict(self) -> dict:
        return _plain(self)


@dataclass(frozen=True)
class InteractiveObservation:
    kind: str
    summary: str = ""
    artifact_paths: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _set(self, kind=_match("observation.kind", self.kind, _ACTION_KIND), summary=_text("observation.summary", self.summary, maxlen=MAX_TEXT),
             artifact_paths=_tuple("observation.artifact_paths", self.artifact_paths, _rel_path, maxlen=32))

    @classmethod
    def from_dict(cls, data: Any) -> "InteractiveObservation":
        return _from_dict(cls, data, {})

    def to_dict(self) -> dict:
        return _plain(self)


@dataclass(frozen=True)
class AdapterResult:
    """What an adapter run produced. ``authority`` is always ``"native"``: nothing in a result is an oracle verdict."""

    run_id: str
    adapter_id: str
    adapter_class: AdapterClass
    status: Status
    native_assertions: Tuple[NativeAssertion, ...] = ()
    artifacts: Tuple[EvidenceArtifact, ...] = ()
    observations: Tuple[InteractiveObservation, ...] = ()
    error_code: Optional[ErrorCode] = None
    error_message: str = ""
    exit_code: Optional[int] = None
    duration_s: float = 0.0
    stdout_tail: str = ""
    stderr_tail: str = ""
    attempts: int = 1
    authority: str = "native"
    schema: str = RESULT_SCHEMA

    def __post_init__(self) -> None:
        _set(self, run_id=_match("run_id", self.run_id, _ID), adapter_id=_match("adapter_id", self.adapter_id, _SLUG),
             adapter_class=_enum("adapter_class", AdapterClass, self.adapter_class), status=_enum("status", Status, self.status),
             native_assertions=_tuple("native_assertions", self.native_assertions, _is(NativeAssertion)),
             artifacts=_tuple("artifacts", self.artifacts, _is(EvidenceArtifact), maxlen=1000),
             observations=_tuple("observations", self.observations, _is(InteractiveObservation), maxlen=1000),
             error_message=_text("error_message", self.error_message, maxlen=MAX_TEXT),
             stdout_tail=_text("stdout_tail", self.stdout_tail, maxlen=MAX_TEXT * 4), stderr_tail=_text("stderr_tail", self.stderr_tail, maxlen=MAX_TEXT * 4))
        if self.error_code is not None:
            _set(self, error_code=_enum("error_code", ErrorCode, self.error_code))
        if self.authority != "native":
            raise ModelError("an adapter result has native authority only; an oracle verdict is a different object")
        if self.schema != RESULT_SCHEMA:
            raise ModelError(f"schema must be {RESULT_SCHEMA}")
        if self.status is Status.UNVERIFIED:
            raise ModelError("an adapter result is never UNVERIFIED; the mapping step assigns that to a canonical assertion")
        if (self.status is Status.ERROR) != (self.error_code is not None):
            raise ModelError("ERROR requires an error_code and no other status may carry one")
        if self.exit_code is not None:
            _num("exit_code", self.exit_code, lo=-255, hi=255, integer=True)
        _num("duration_s", self.duration_s, lo=0.0, hi=1e7)
        _num("attempts", self.attempts, lo=1, hi=HARD_CAPS_RAW["max_retries"] + 1, integer=True)
        ids = [a.native_id for a in self.native_assertions]
        if len(set(ids)) != len(ids):
            raise ModelError("native_assertions has duplicate native ids")
        if self.status is Status.PASS and (not self.native_assertions and self.adapter_class is AdapterClass.SUITE):
            raise ModelError("a suite result cannot PASS without a native assertion")
        if self.status is Status.PASS and any(a.status is not Status.PASS for a in self.native_assertions):
            raise ModelError("a PASS result cannot contain a native assertion that did not pass")

    @classmethod
    def from_dict(cls, data: Any) -> "AdapterResult":
        return _from_dict(cls, data, {
            "adapter_class": lambda v: _enum("adapter_class", AdapterClass, v), "status": lambda v: _enum("status", Status, v),
            "native_assertions": lambda v: _tuple("native_assertions", v, lambda n, x: NativeAssertion.from_dict(x)),
            "artifacts": lambda v: _tuple("artifacts", v, lambda n, x: EvidenceArtifact.from_dict(x), maxlen=1000),
            "observations": lambda v: _tuple("observations", v, lambda n, x: InteractiveObservation.from_dict(x), maxlen=1000),
            "error_code": lambda v: None if v is None else _enum("error_code", ErrorCode, v)})

    def to_dict(self) -> dict:
        return _plain(self)

    def digest(self) -> str:
        return digest(self)


def _is(cls):
    def check(name: str, value: Any):
        if not isinstance(value, cls):
            raise ModelError(f"{name} must be a {cls.__name__}")
        return value
    return check


def aggregate_status(assertions: Tuple[NativeAssertion, ...]) -> Status:
    """Native aggregate: ERROR over FAIL over UNKNOWN over SKIP; PASS only when there is at least one assertion and all pass."""
    if not assertions:
        return Status.UNKNOWN
    statuses = {a.status for a in assertions}
    for worse in (Status.ERROR, Status.FAIL, Status.UNKNOWN, Status.SKIP):
        if worse in statuses:
            return worse
    return Status.PASS
