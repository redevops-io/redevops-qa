# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The conformance suite: the release-critical gate that makes contracts ``qa/v1`` and the harness neutral mirror one
contract (ADR A.2.5 and A.2.7).

* :mod:`items` enumerates what is checked, from the pinned vector files and the pinned packages themselves;
* :mod:`checks` runs one item and raises :class:`ConformanceFailure` with a stable code and the concrete mismatch;
* :mod:`pytest_plugin` collects the pytest outcome per check (collected, passed, failed, skipped);
* :mod:`receipt` builds and :mod:`verify` verifies the machine-readable ``compat-receipt/1``;
* :mod:`report` turns the failures of a run into a divergence report;
* :mod:`cli` is the command line (``run``, ``verify``).
"""
