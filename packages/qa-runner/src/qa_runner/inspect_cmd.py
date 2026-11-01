# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``redevops-qa inspect``: what is in a bundle (files, digests, tool versions, lanes) and the heads of the chains inside it. It lists; it does not judge and it never
recomputes a verdict. Every string that came from the bundle is passed through ``safe_text``."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from qa_evidence.build import BuildError, read_files
from qa_evidence.canon import CanonError, loads_strict, safe_text
from qa_evidence.inspector import inspect_bundle
from qa_evidence.sources import SourceError

RECORD_SUFFIX = "/native/run-record.json"


def chain_heads(files: Dict[str, bytes]) -> List[Dict[str, Any]]:
    """For each harness run record in the bundle: how many events and receipts it holds, the last event hash, the last receipt link, and how the run was sealed.
    Read from the record as stored; the integrity of the chains is checked by ``verify``, not here."""
    out = []
    for path in sorted(p for p in files if p.endswith(RECORD_SUFFIX)):
        try:
            rec = loads_strict(files[path])
            events, links = rec["events"], rec["receipt_links"]
            sealed = events[-1] if events and events[-1].get("kind") == "RunSealed" else None
            out.append({"lane": path.split("/")[1], "events": len(events), "event_head": events[-1].get("event_hash") if events else None,
                        "receipts": len(links), "receipt_head": links[-1].get("link_hash") if links else None,
                        "sealed": sealed is not None, "sealed_outcome": (sealed or {}).get("payload", {}).get("classification", {}).get("outcome")})
        except (CanonError, KeyError, TypeError, AttributeError):
            out.append({"lane": path.split("/")[1], "events": None, "event_head": None, "receipts": None, "receipt_head": None, "sealed": False, "sealed_outcome": None})
    return out


def inspect_text(location: str, *, anchor: Optional[str] = None, plan_digest: Optional[str] = None) -> str:
    ins = inspect_bundle(location, anchor=anchor, plan_digest=plan_digest)
    v = ins.verification
    t = lambda x, n=200: safe_text(x, n)         # noqa: E731
    lines = [f"bundle {t(location)}: {v.form}, {v.file_count} file(s), manifest digest {t(v.manifest_digest)}",
             "verification: " + ("OK, internally consistent" if v.ok else f"FAILED, {len(v.findings)} finding(s): " + ", ".join(sorted({t(f.code) for f in v.findings}))),
             f"anchor: {v.anchor.notice}"]
    if v.plan is not None:
        lines.append(f"plan digest: {v.plan.notice}")
    s = ins.summary
    if s is not None:
        lines.append(f"run {t(s['run_id'])}  {t(s['started_at'])} .. {t(s['finished_at'])}  plan digest {t(s['plan_digest'])}")
        env = ", ".join(f"{t(k)} {t(val)}" for k, val in sorted(s["environment"].items()))
        lines.append(f"environment: {env}")
        if s["tools"]:
            lines.append("tools: " + ", ".join(f"{t(k)} {t(val)}" for k, val in sorted(s["tools"].items())))
        iv = s["independent_verdict"]
        lines.append(f"verdict: {t(iv['outcome'])} ({t(iv['reason_code'])}) by {t(iv['provenance']['verifier']['id'])} {t(iv['provenance']['verifier']['version'])}")
        for lane in s["lanes"]:
            n = lane["native"]
            lines.append(f"lane {t(lane['lane_id'])}: {t(lane['engine']['name'])} {t(lane['engine']['version'])}, engine reported {n['status']} ({t(n['raw_status'], 64)}), "
                         f"independent verdicts {lane['independent_verdicts']}")
        for d in s["engine_verifier_disagreements"]:
            lines.append(f"  ENGINE_VERIFIER_DISAGREE lane {t(d['lane_id'])}: native {t(d['native_status'])}, verdicts {t(', '.join(d['verdict_states']) or 'none')}")
    try:
        files = read_files(location)
    except (BuildError, SourceError):
        files = {}
    for h in chain_heads(files):
        lines.append(f"chain lane {t(h['lane'])}: {h['events']} events, head {t(h['event_head'])}; {h['receipts']} receipts, head {t(h['receipt_head'])}; "
                     f"{'sealed, harness outcome ' + t(h['sealed_outcome']) if h['sealed'] else 'NOT sealed'}")
    lines.append("files:")
    for f in ins.files:
        lines.append(f"  {t(f['role']):16} {f['size']:>9}  {t(f['digest'])}  {t(f['path'])}")
    return "\n".join(lines) + "\n"
