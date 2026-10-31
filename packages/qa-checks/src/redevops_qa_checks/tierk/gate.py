# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The adapter's route into the disposable cluster.

``TierKGate`` is built from a ``GuardedSession`` (and therefore only from a cluster the guard accepted). The adapter calls
``verify_proof`` when a tier K workspace is opened, ``run_check`` for each tier K subject, and ``close`` at the end. A tier K
subject must name a tier K program (a program that declares a collector); the collector reads the cluster through the
session, and the program turns what was read into an observed value that carries its lane.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Any, Callable, List, Sequence

from ..canonical import canonical_bytes, sha256_ref
from ..engine import MAX_VALUE_BYTES, CheckEngine, Outcome
from ..errors import LimitExceeded, PolicyBlocked
from ..manifests import freeze
from ..not_expressible import ensure_expressible
from ..program_input import ProgramInput
from ..registry import refuse_expected
from .collectors import COLLECTORS, NEEDS_INPUTS
from .guard import GuardedSession


class TierKGate:
    def __init__(self, session: GuardedSession) -> None:
        if not isinstance(session, GuardedSession):
            raise PolicyBlocked("a gate needs a guarded session", guard_code="SESSION_REQUIRED")
        self._s = session
        self._cleanups: List[Callable[[], Sequence[str]]] = []

    @property
    def lane(self) -> str:
        return self._s.lane

    def verify_proof(self, disposable_proof_ref: str) -> None:
        current = self._s.verify(version=False)
        if disposable_proof_ref != current:
            raise PolicyBlocked("the disposable_proof_ref does not match this cluster", guard_code="PROOF_MISMATCH")

    def register_cleanup(self, fn: Callable[[], Sequence[str]]) -> None:
        """A callable that removes what this session created and returns the ids of anything it could not remove."""
        self._cleanups.append(fn)

    def run_check(self, engine: CheckEngine, subject: Mapping) -> Outcome:
        refuse_expected(subject, "check subject")
        ref = subject["check_program_ref"]
        ensure_expressible(ref.get("id"))
        if subject.get("tier") != "K":
            raise PolicyBlocked("the gate runs tier K subjects only", guard_code="TIER_MISMATCH")
        spec = engine.registry.resolve(ref)                       # hash verified before anything is read or collected
        if spec.tier != "K" or spec.collector not in COLLECTORS:
            raise PolicyBlocked("a tier K subject must name a tier K program", guard_code="TIER_MISMATCH", program=spec.id)
        inputs = list(subject.get("inputs") or ())
        digests = ()
        data = ProgramInput()
        if spec.collector in NEEDS_INPUTS or inputs:
            loaded, resolution, count, digests = engine.load_inputs(inputs)
            if loaded is None:
                return Outcome(resolution=resolution, match_count=count, inputs=digests)
            data = loaded
        observations = COLLECTORS[spec.collector](self._s, data.manifests)
        data = replace(data, cluster=tuple(freeze(o) for o in observations))
        value = engine.registry.run(ref, data)
        raw = canonical_bytes(value)
        if len(raw) > MAX_VALUE_BYTES:
            raise LimitExceeded(f"the observed value is {len(raw)} bytes, over the {MAX_VALUE_BYTES} byte bound", size=len(raw))
        return Outcome(resolution="RESOLVED", match_count=1, value=value, value_sha256=sha256_ref(raw),
                       inputs=tuple(digests) + (("disposable-proof", self._s.proof_ref),))

    def reset(self, scope: str) -> None:
        self._run_cleanups()

    def _run_cleanups(self) -> List[str]:
        leaked: List[str] = []
        for fn in reversed(self._cleanups):
            leaked.extend(fn())
        self._cleanups.clear() if not leaked else None
        return leaked

    def close(self) -> Sequence[str]:
        return self._run_cleanups()
