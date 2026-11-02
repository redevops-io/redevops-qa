# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Names, versions, caps and fixed texts of the evidence bundle format. Nothing here reads a clock, a host or an environment variable."""
from __future__ import annotations

import re

PACKAGE_VERSION = "0.1.0.dev0"

MANIFEST_SCHEMA = "qa-evidence/bundle-manifest"
REPORT_SCHEMA = "qa-evidence/run-report"
ANCHOR_SCHEMA = "qa-evidence/anchor"

#: The schema version this reader understands, as MAJOR.MINOR. A different MAJOR is refused. A newer MINOR is read under the rules in
#: ``schemas.py`` / the package README: unknown fields are refused wherever they are security-sensitive and tolerated (and listed) only inside
#: the declared informational objects.
SUPPORTED_MAJOR = 1
SUPPORTED_MINOR = 0
SCHEMA_VERSION = f"{SUPPORTED_MAJOR}.{SUPPORTED_MINOR}"
VERSION_RE = re.compile(r"^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$")

MANIFEST_NAME = "bundle-manifest.json"
REPORT_NAME = "report.json"
ANCHOR_NAME = "anchor.json"
FORMAT_DOC_NAME = "BUNDLE-FORMAT.txt"
#: Top-level names that exist outside the manifest's file list: the manifest cannot list itself, and the anchor sidecar is, by
#: design, not covered by the manifest (it holds the digest OF the manifest).
RESERVED_UNLISTED = frozenset({MANIFEST_NAME, ANCHOR_NAME})

ROLES = ("report", "native-artifact", "assertion-lock", "observation", "record", "log", "verifier", "documentation", "other")
LANE_STATUSES = ("NATIVE_PASS", "NATIVE_FAIL", "NATIVE_ERROR", "NATIVE_SKIPPED", "NATIVE_TIMEOUT", "NATIVE_UNAVAILABLE")
VERDICT_STATES = ("VERIFIED", "FAILED", "INCONCLUSIVE", "UNACCOUNTED")
OUTCOMES = ("VERIFIED", "FAILED", "INCONCLUSIVE")
#: Only a CI artifact attestation is an anchor type of this format version. Signed bundles are not supported and are not accepted as a type.
ANCHOR_TYPES = ("ci-artifact-attestation",)
ASSERTION_LOCK_NAME = "assertion-lock.json"
#: Everything under lanes/<lane id>/native/ is what that lane's engine wrote; nothing else may live there and no verdict may be based on it.
NATIVE_DIR_RE = re.compile(r"lanes/[^/]+/native/.+")
#: Native statuses under which a lane ran to completion. Any other status caps the run outcome at INCONCLUSIVE.
COMPLETING_STATUSES = ("NATIVE_PASS", "NATIVE_FAIL")

#: Closed vocabulary of reason codes per verdict state, and the run-level code per outcome.
REASON_CODES = {
    "VERIFIED": ("EQUALS_EXPECTED", "PREDICATE_HOLDS"),
    "FAILED": ("EXPECTED_VALUE_DIFFERS", "PREDICATE_VIOLATED"),
    "INCONCLUSIVE": ("EVIDENCE_MISSING", "EVIDENCE_UNUSABLE", "ASSERTION_INTEGRITY", "VERIFIER_ERROR", "TEST_DOUBLE", "EVIDENCE_INCOMPLETE"),
    "UNACCOUNTED": ("NO_RESULT_RECORDED",),
}
RUN_REASONS = {"VERIFIED": ("ALL_ASSERTIONS_VERIFIED",), "FAILED": ("ASSERTION_FAILED",),
               "INCONCLUSIVE": ("NOT_ALL_ASSERTIONS_VERIFIED", "ENGINE_DID_NOT_COMPLETE", "NATIVE_FAIL_VERIFIED_ASSERTIONS")}

# ---- caps (documented in the README; the verifier refuses anything above them, and refuses a manifest that declares more) -------------
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class Limits:
    """Caps applied while a bundle is read. Instances are immutable; the defaults are the documented caps."""

    __slots__ = ("max_files", "max_file_bytes", "max_total_bytes", "max_path_bytes", "max_component_bytes", "max_json_bytes",
                 "max_json_depth", "max_string_chars", "max_items")

    def __init__(self, max_files=4096, max_file_bytes=64 * 1024 * 1024, max_total_bytes=256 * 1024 * 1024, max_path_bytes=100,
                 max_component_bytes=64, max_json_bytes=8 * 1024 * 1024, max_json_depth=24, max_string_chars=8192, max_items=20000):
        object.__setattr__(self, "max_files", max_files)
        object.__setattr__(self, "max_file_bytes", max_file_bytes)
        object.__setattr__(self, "max_total_bytes", max_total_bytes)
        object.__setattr__(self, "max_path_bytes", max_path_bytes)
        object.__setattr__(self, "max_component_bytes", max_component_bytes)
        object.__setattr__(self, "max_json_bytes", max_json_bytes)
        object.__setattr__(self, "max_json_depth", max_json_depth)
        object.__setattr__(self, "max_string_chars", max_string_chars)
        object.__setattr__(self, "max_items", max_items)

    def __setattr__(self, name, value):
        raise AttributeError("Limits is immutable")

    def as_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


DEFAULT_LIMITS = Limits()

# ---- fixed texts ---------------------------------------------------------------------------------------------------------------------
ANCHOR_ABSENT_NOTICE = "no external anchor: integrity against deliberate re-forging NOT established"
ANCHOR_DECLARED_NOTICE = ("anchor data is present in the bundle but was NOT checked against an external value: "
                          "integrity against deliberate re-forging NOT established")
ANCHOR_VERIFIED_NOTICE = ("the recomputed manifest digest matches the supplied anchor value; this tool did not authenticate where that "
                          "value came from (it does not implement or check any attestation), so this is a match, not proof of integrity")
ANCHOR_MISMATCH_NOTICE = "the recomputed manifest digest does NOT equal the supplied anchor value: the bundle is not the one that was anchored"

DIGEST_ORIGIN_NOTICE = ("this digest is only meaningful as an anchor if it is obtained from a trusted external channel that the producer of the "
                        "bundle cannot write; a digest taken from the same bundle proves nothing about it")
PLAN_ABSENT_NOTICE = ("frozen assertion set not checked against an external plan digest: the set is declared by the producer of the bundle "
                      "(an assertion removed together with every digest would not be noticed)")
PLAN_VERIFIED_NOTICE = "the plan digest in the report matches the supplied value; this tool did not authenticate where that value came from"
PLAN_MISMATCH_NOTICE = "the plan digest in the report does NOT match the supplied value: this is not the frozen assertion set that was asked for"
PLAN_INVALID_NOTICE = "the supplied plan digest is malformed: the frozen assertion set was not checked"

INTEGRITY_STATEMENT = (
    "File digests and the manifest are UNKEYED hashes. They detect accidental changes and partial edits. They do NOT detect deliberate "
    "re-forging: anyone who can rewrite the whole bundle can recompute every digest and the manifest. Integrity against deliberate "
    "re-forging is established only when the digest of bundle-manifest.json is compared with a value published outside the bundle "
    "(for example through a CI artifact attestation); signed bundles are not part of this format version.")

ANCHOR_BLOCK_STATEMENT = (
    "The digest of this manifest is not stored in it. An external value for it can be supplied at verification time, and an optional "
    "sidecar file (anchor.json, not covered by this manifest) can carry the anchor type, an anchor reference and the digest as data. "
    "The sidecar alone does not establish anything: it can be rewritten together with the bundle.")

LIMITATION_TEXTS = {
    "evidence-not-correctness": (
        "The verdict states that the frozen assertions were evaluated by an independent verifier over recorded observations. It does "
        "not establish that the application under test is correct."),
    "native-result-not-verdict": (
        "A native engine result is the engine's own report. It is never converted into a verified verdict; only the independent "
        "verifier's verdict, with its provenance, counts."),
    "unkeyed-hash-chain": INTEGRITY_STATEMENT,
}
REQUIRED_LIMITATION_IDS = tuple(sorted(LIMITATION_TEXTS))

FORMAT_DOC = """\
QA EVIDENCE BUNDLE (format qa-evidence, schema version %s)

This directory (or tar archive) is a portable record of one QA run. It is read offline: nothing here is fetched.

Files
  bundle-manifest.json   every other file with its sha256 and size, the run ids, the engine lanes, tool versions, OS and architecture,
                         the assertion digests, and an explicit anchor block
  report.json            the run report (schema qa-evidence/run-report): per-lane native results, assertion accounting, the independent
                         verdict with provenance, redaction notes and limitations
  assertion-lock.json    the frozen assertions (id, lane, digest); its sha256 is the assertion-set digest and the plan digest
  anchor.json            optional; data only (anchor type, anchor reference, manifest digest); not covered by the manifest
  everything else        native artifacts, recorded observations, logs

What the digests do and do not show
  %s

Frozen assertions
  The assertion set is declared by whoever produced the bundle. Only a plan digest obtained from outside the bundle (python -m qa_evidence
  verify BUNDLE --plan-digest sha256:HEX) shows that it is the set that was asked for; without one, verification says so.

Native results and verdicts
  A lane's native result is the engine's own report. A verdict is produced by an independent verifier over recorded observations and
  frozen assertions, and carries its provenance (verifier, version, assertion digest, evidence digest). A native pass is never a
  verified verdict. A verified verdict does not show that the application under test is correct.

Verifying
  python -m qa_evidence verify BUNDLE [--anchor sha256:HEX]
""" % (SCHEMA_VERSION, INTEGRITY_STATEMENT)
