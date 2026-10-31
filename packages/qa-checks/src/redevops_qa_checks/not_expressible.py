# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Properties that cannot be checked here, named so that asking for one is refused as not expressible (``UnsupportedOperation``)
and never answered with a pass. Each entry says why: a closed-world property needs the whole set of what is allowed,
signature admission needs signed images and a signature service, certificate issuance and secret synchronisation need controllers
the disposable cluster does not run, the metadata-endpoint proof needs a service that does not exist in it, and name-based probes
cannot tell a policy block from a failed name lookup without an internet."""
from __future__ import annotations

from typing import Mapping

from .errors import Unsupported

NOT_EXPRESSIBLE: Mapping[str, str] = {
    "closed-world.allow-list-completeness": "a property over everything that is not listed; the disposable cluster can show what is allowed, not that nothing else is",
    "admission.signature-verification": "stand-in images are not signed and no signature service is reachable; only the policy object's acceptance can be observed",
    "traffic.metadata-endpoint-proof": "no node metadata service exists in the disposable cluster; the compiled policy entry can be observed, not traffic to it",
    "certificates.issuance": "certificate controllers are not running (CRD-only)",
    "secrets.external-sync": "the external secrets controller is not running (CRD-only)",
    "policy.background-scan": "the background, cleanup and reports controllers are disabled",
    "traffic.name-based-unreachable": "without an internet a name that fails to resolve looks the same as a policy block; use an IP-literal probe",
    "persistence.volume-write-semantics": "storage classes differ from the target platform; ownership on the local volume was not established",
}


def ensure_expressible(program_id: object) -> None:
    if type(program_id) is str and program_id in NOT_EXPRESSIBLE:
        raise Unsupported(f"{program_id} is not expressible: {NOT_EXPRESSIBLE[program_id]}", program=program_id)
