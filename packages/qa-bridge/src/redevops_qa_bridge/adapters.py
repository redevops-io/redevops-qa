# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Adapter shims: one component usable through both protocol forms.

``QAAdapter`` / ``CheckAdapter`` (contracts) and ``NeutralQAAdapter`` / ``NeutralCheckAdapter`` (harness) are the same
operations with the same names, parameter names and ``api_version``. A component written against one is wrapped to be
used through the other: every argument and result is converted as plain data (``convert``), and typed errors cross by
their ``code`` (``errormap``). No class instance of one side reaches the other.

A shim refuses (``AdapterRefused``) a component that lacks a protocol member or declares another ``api_version``.
"""
from __future__ import annotations

from typing import Any, Sequence

from . import deps
from .convert import from_contracts, from_contracts_sequence, to_contracts, to_contracts_sequence
from .errormap import contracts_to_neutral, neutral_to_contracts
from .errors import AdapterRefused

QA_MEMBERS = ("adapter_id", "adapter_version", "api_version", "open_session", "observe", "locate", "act", "assert_",
              "capture", "reset", "close_session")
CHECK_MEMBERS = ("adapter_id", "adapter_version", "api_version", "open_workspace", "resolve", "run_check", "capture",
                 "reset", "close_workspace")
BLOB_MEMBERS = ("put", "get", "exists", "size")
REDACTOR_MEMBERS = ("policy_id", "redact")


def _require(inner: Any, members: Sequence[str], api_version: str = "", what: str = "component") -> None:
    missing = [m for m in members if not hasattr(inner, m)]
    if missing:
        raise AdapterRefused(f"{what} lacks {missing}", missing=missing)
    if api_version and getattr(inner, "api_version", None) != api_version:
        raise AdapterRefused(f"{what} declares api_version {getattr(inner, 'api_version', None)!r}, expected "
                             f"{api_version!r}", api_version=str(getattr(inner, "api_version", None)))


class _Identity:
    """adapter_id / adapter_version / api_version are read through from the wrapped component."""

    _inner: Any

    @property
    def adapter_id(self) -> str:
        return self._inner.adapter_id

    @property
    def adapter_version(self) -> str:
        return self._inner.adapter_version

    @property
    def api_version(self) -> str:
        return self._inner.api_version


# -- QAAdapter ----------------------------------------------------------------------------------------------------------

class NeutralQAAdapterFromContracts(_Identity):
    """A contracts-typed ``QAAdapter`` used through ``NeutralQAAdapter`` (what the harness runner calls)."""

    def __init__(self, inner: Any) -> None:
        c = deps.contracts_qa()
        _require(inner, QA_MEMBERS, c.QA_ADAPTER_API_VERSION, "contracts QAAdapter")
        self._inner = inner

    def open_session(self, profile):
        arg = to_contracts(profile)
        with contracts_to_neutral():
            return from_contracts(self._inner.open_session(arg))

    def observe(self, s, req):
        a, b = to_contracts(s), to_contracts(req)
        with contracts_to_neutral():
            return from_contracts(self._inner.observe(a, b))

    def locate(self, s, target, *, mode):
        a, b, m = to_contracts(s), to_contracts(target), to_contracts(mode)
        with contracts_to_neutral():
            return from_contracts(self._inner.locate(a, b, mode=m))

    def act(self, s, action, target):
        a, b, t = to_contracts(s), to_contracts(action), to_contracts(target)
        with contracts_to_neutral():
            return from_contracts(self._inner.act(a, b, t))

    def assert_(self, s, subject):
        a, b = to_contracts(s), to_contracts(subject)
        with contracts_to_neutral():
            return from_contracts(self._inner.assert_(a, b))

    def capture(self, s, kinds):
        a, ks = to_contracts(s), to_contracts_sequence(tuple(kinds))
        with contracts_to_neutral():
            return from_contracts_sequence(tuple(self._inner.capture(a, ks)))

    def reset(self, s, scope):
        a, sc = to_contracts(s), to_contracts(scope)
        with contracts_to_neutral():
            return from_contracts(self._inner.reset(a, sc))

    def close_session(self, s):
        a = to_contracts(s)
        with contracts_to_neutral():
            return from_contracts(self._inner.close_session(a))


class ContractsQAAdapterFromNeutral(_Identity):
    """A neutral ``NeutralQAAdapter`` used through the contracts ``QAAdapter``."""

    def __init__(self, inner: Any) -> None:
        n = deps.neutral_qa()
        _require(inner, QA_MEMBERS, n.schemas.ADAPTER_API_VERSION, "neutral QAAdapter")
        self._inner = inner

    def open_session(self, profile):
        arg = from_contracts(profile)
        with neutral_to_contracts():
            return to_contracts(self._inner.open_session(arg))

    def observe(self, s, req):
        a, b = from_contracts(s), from_contracts(req)
        with neutral_to_contracts():
            return to_contracts(self._inner.observe(a, b))

    def locate(self, s, target, *, mode):
        a, b, m = from_contracts(s), from_contracts(target), from_contracts(mode)
        with neutral_to_contracts():
            return to_contracts(self._inner.locate(a, b, mode=m))

    def act(self, s, action, target):
        a, b, t = from_contracts(s), from_contracts(action), from_contracts(target)
        with neutral_to_contracts():
            return to_contracts(self._inner.act(a, b, t))

    def assert_(self, s, subject):
        a, b = from_contracts(s), from_contracts(subject)
        with neutral_to_contracts():
            return to_contracts(self._inner.assert_(a, b))

    def capture(self, s, kinds):
        a, ks = from_contracts(s), from_contracts_sequence(tuple(kinds))
        with neutral_to_contracts():
            return to_contracts_sequence(tuple(self._inner.capture(a, ks)))

    def reset(self, s, scope):
        a, sc = from_contracts(s), from_contracts(scope)
        with neutral_to_contracts():
            return to_contracts(self._inner.reset(a, sc))

    def close_session(self, s):
        a = from_contracts(s)
        with neutral_to_contracts():
            return to_contracts(self._inner.close_session(a))


# -- CheckAdapter -------------------------------------------------------------------------------------------------------

class NeutralCheckAdapterFromContracts(_Identity):
    """A contracts-typed ``CheckAdapter`` used through ``NeutralCheckAdapter``."""

    def __init__(self, inner: Any) -> None:
        c = deps.contracts_qa()
        _require(inner, CHECK_MEMBERS, c.CHECK_ADAPTER_API_VERSION, "contracts CheckAdapter")
        self._inner = inner

    def open_workspace(self, profile):
        a = to_contracts(profile)
        with contracts_to_neutral():
            return from_contracts(self._inner.open_workspace(a))

    def resolve(self, w, ref):
        a, b = to_contracts(w), to_contracts(ref)
        with contracts_to_neutral():
            return from_contracts(self._inner.resolve(a, b))

    def run_check(self, w, subject):
        a, b = to_contracts(w), to_contracts(subject)
        with contracts_to_neutral():
            return from_contracts(self._inner.run_check(a, b))

    def capture(self, w, kinds):
        a, ks = to_contracts(w), to_contracts_sequence(tuple(kinds))
        with contracts_to_neutral():
            return from_contracts_sequence(tuple(self._inner.capture(a, ks)))

    def reset(self, w, scope):
        a, sc = to_contracts(w), to_contracts(scope)
        with contracts_to_neutral():
            return from_contracts(self._inner.reset(a, sc))

    def close_workspace(self, w):
        a = to_contracts(w)
        with contracts_to_neutral():
            return from_contracts(self._inner.close_workspace(a))


class ContractsCheckAdapterFromNeutral(_Identity):
    """A neutral ``NeutralCheckAdapter`` used through the contracts ``CheckAdapter``."""

    def __init__(self, inner: Any) -> None:
        n = deps.neutral_qa()
        _require(inner, CHECK_MEMBERS, n.schemas.CHECK_ADAPTER_API_VERSION, "neutral CheckAdapter")
        self._inner = inner

    def open_workspace(self, profile):
        a = from_contracts(profile)
        with neutral_to_contracts():
            return to_contracts(self._inner.open_workspace(a))

    def resolve(self, w, ref):
        a, b = from_contracts(w), from_contracts(ref)
        with neutral_to_contracts():
            return to_contracts(self._inner.resolve(a, b))

    def run_check(self, w, subject):
        a, b = from_contracts(w), from_contracts(subject)
        with neutral_to_contracts():
            return to_contracts(self._inner.run_check(a, b))

    def capture(self, w, kinds):
        a, ks = from_contracts(w), from_contracts_sequence(tuple(kinds))
        with neutral_to_contracts():
            return to_contracts_sequence(tuple(self._inner.capture(a, ks)))

    def reset(self, w, scope):
        a, sc = from_contracts(w), from_contracts(scope)
        with neutral_to_contracts():
            return to_contracts(self._inner.reset(a, sc))

    def close_workspace(self, w):
        a = from_contracts(w)
        with neutral_to_contracts():
            return to_contracts(self._inner.close_workspace(a))


# -- BlobStore / BlobSink and Redactor (bytes and strings only; the call shape differs: media_type is keyword-only in
# -- contracts and positional-or-keyword in the neutral protocol) ----------------------------------------------------------

class NeutralBlobSinkFromContracts:
    """A contracts ``BlobStore`` used as the neutral ``BlobSink``."""

    def __init__(self, inner: Any) -> None:
        _require(inner, BLOB_MEMBERS, what="contracts BlobStore")
        self._inner = inner

    def put(self, data: bytes, media_type: str) -> str:
        with contracts_to_neutral():
            return self._inner.put(data, media_type=media_type)

    def get(self, digest: str) -> bytes:
        with contracts_to_neutral():
            return self._inner.get(digest)

    def exists(self, digest: str) -> bool:
        with contracts_to_neutral():
            return self._inner.exists(digest)

    def size(self, digest: str) -> int:
        with contracts_to_neutral():
            return self._inner.size(digest)


class ContractsBlobStoreFromNeutral:
    """A neutral ``BlobSink`` used as the contracts ``BlobStore``."""

    def __init__(self, inner: Any) -> None:
        _require(inner, BLOB_MEMBERS, what="neutral BlobSink")
        self._inner = inner

    def put(self, data: bytes, *, media_type: str) -> str:
        with neutral_to_contracts():
            return self._inner.put(data, media_type)

    def get(self, digest: str) -> bytes:
        with neutral_to_contracts():
            return self._inner.get(digest)

    def exists(self, digest: str) -> bool:
        with neutral_to_contracts():
            return self._inner.exists(digest)

    def size(self, digest: str) -> int:
        with neutral_to_contracts():
            return self._inner.size(digest)


class NeutralRedactorFromContracts:
    """A contracts ``Redactor`` used as the neutral ``Redactor``."""

    def __init__(self, inner: Any) -> None:
        _require(inner, REDACTOR_MEMBERS, what="contracts Redactor")
        self._inner = inner

    @property
    def policy_id(self) -> str:
        return self._inner.policy_id

    def redact(self, data: bytes, media_type: str) -> bytes:
        with contracts_to_neutral():
            return self._inner.redact(data, media_type=media_type)


class ContractsRedactorFromNeutral:
    """A neutral ``Redactor`` used as the contracts ``Redactor``."""

    def __init__(self, inner: Any) -> None:
        _require(inner, REDACTOR_MEMBERS, what="neutral Redactor")
        self._inner = inner

    @property
    def policy_id(self) -> str:
        return self._inner.policy_id

    def redact(self, data: bytes, *, media_type: str) -> bytes:
        with neutral_to_contracts():
            return self._inner.redact(data, media_type)
