# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Derived variants: legal payloads built from the frozen golden cases by data-only edits.

The golden cases fix one payload per schema. Both implementations must also agree on the legal payloads around them, in
particular on the optional fields of the three repository types qa/v1 reuses (``Check``, ``EvidenceRef``, ``SecretRef``).
Each variant names its base case, the edit, and the side it is meant to be loaded on first. ``control`` variants are
expected to agree on both sides and guard the probes against a harness that fails for the wrong reason.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Any, Callable, Dict, Tuple

PIN_Z = "zz-ref@1#sha256:" + "0" * 63 + "7"
PIN_A = "aa-ref@1#sha256:" + "0" * 63 + "6"


@dataclass(frozen=True)
class Variant:
    variant_id: str
    base_case: str
    edit: Callable[[Dict[str, Any]], None]
    sides: Tuple[str, ...]          # which side loads the edited payload first: "contracts", "neutral"
    why: str
    control: bool = False


def _check_detail(d):
    d["check"]["detail"] = "free wording"


def _check_refs_unsorted(d):
    d["check"]["evidence_refs"] = [PIN_Z, PIN_A]


def _evidence_defaults_omitted(d):
    for key in ("screenshot_ref", "a11y_snapshot_ref"):
        for field in ("modality", "ref_type"):
            d[key].pop(field, None)


def _secret_without_path(d):
    a = d["steps"][0]["action"]
    a.pop("value", None)
    a["kind"] = "fill"
    a["secret_ref"] = {"provider": "vault", "key": "k"}


def _secret_complete(d):
    a = d["steps"][0]["action"]
    a.pop("value", None)
    a["kind"] = "fill"
    a["secret_ref"] = {"provider": "vault", "key": "k", "path": "ci/app", "namespace": "ns", "version": "3"}


def _explicit_null(d):
    d["fixture_snapshot_id"] = None


def _nfd(d):
    d["steps"][0]["intent"] = unicodedata.normalize("NFD", "Sauvegarder le café")


def _custody_changes(d):
    d.setdefault("custody", {})["author"] = "someone else"
    d["custody"]["reviewer"] = "another reviewer"


def _recovery_order(d):
    d["steps"][0]["permitted_recovery"] = ["SEMANTIC_LOCATOR", "CHECKPOINT_RESUME"]


VARIANTS = (
    Variant("check-detail-wording", "assertion_result_pass", _check_detail, ("contracts", "neutral"),
            "Check.detail is wording: contracts excludes it from the canonical form, so a payload that carries it must "
            "hash alike on both sides"),
    Variant("check-evidence-refs-unsorted", "assertion_result_pass", _check_refs_unsorted, ("contracts", "neutral"),
            "Check.evidence_refs is a set of pins sorted by value in the contracts canonical form"),
    Variant("evidence-ref-defaults-omitted", "observation", _evidence_defaults_omitted, ("neutral",),
            "an EvidenceRef that omits modality and ref_type: contracts fills the defaults ('text', 'evidence') into the "
            "hashed form"),
    Variant("secret-ref-without-path", "test_spec_ui", _secret_without_path, ("contracts", "neutral"),
            "a SecretRef with no path: contracts hashes path as the empty string"),
    Variant("secret-ref-complete", "test_spec_ui", _secret_complete, ("contracts", "neutral"),
            "control: a SecretRef with every field set", control=True),
    Variant("explicit-null-optional", "checkpoint", _explicit_null, ("contracts", "neutral"),
            "control: an explicit null equals an absent optional field", control=True),
    Variant("nfd-string", "test_spec_ui", _nfd, ("contracts", "neutral"),
            "control: an NFD spelling hashes as its NFC form", control=True),
    Variant("custody-changes", "test_spec_ui", _custody_changes, ("contracts", "neutral"),
            "control: custody fields never enter the hash", control=True),
    Variant("set-order-of-enums", "test_spec_ui", _recovery_order, ("contracts", "neutral"),
            "control: the listed order of an enum set is not identity", control=True),
)
