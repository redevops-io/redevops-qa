# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Text and HTML renderers. Every value that came from a bundle passes through ``safe_text`` (control, bidi and zero-width characters
become visible escapes) and, in HTML, ``html.escape``. The HTML is one file: inline style, no script, no image, no font, no link to
anything, and a Content-Security-Policy that forbids loading any resource."""
from __future__ import annotations

import html
from typing import Any, Iterable, List

from .canon import safe_text
from .inspector import Inspection

_RULE = "-" * 78


def _t(value: Any, limit: int = 300) -> str:
    return safe_text(value, limit)


#: What a caller that did NOT recompute the verdicts (``verdicts_recomputed=False``) shows instead of "Verification : OK" and the "independent verdict" wording: the files, digests and accounting
#: were checked, and nothing says the verdicts are true.
NOT_RECOMPUTED_OK = "files, digests and accounting are consistent; the verdicts were NOT recomputed by this command and are not independently verified"
NOT_RECOMPUTED_CLOSING = "These verdicts are the runner's own, as recorded in the bundle; no command recomputed them here. It does not mean the application under test is correct."


def render_text(ins: Inspection, *, verdicts_recomputed: bool = True) -> str:
    v = ins.verification
    lines: List[str] = ["QA EVIDENCE BUNDLE", _RULE]
    lines.append("Verification : " + (("OK - internally consistent" if verdicts_recomputed else NOT_RECOMPUTED_OK) if v.ok else f"FAILED - {len(v.findings)} finding(s)"))
    lines.append("External anchor: " + v.anchor.notice)
    if v.plan is not None:
        lines.append("Frozen assertion set: " + v.plan.notice)
    lines.append(f"Anchor state  : {v.anchor.state}" + (f" (type {_t(v.anchor.anchor_type)}, reference {_t(v.anchor.reference)})" if v.anchor.anchor_type else ""))
    lines.append(f"Manifest digest: {_t(v.manifest_digest)}")
    lines.append(f"Form, files   : {v.form}, {v.file_count} file(s)")
    s = ins.summary
    if s is None:
        lines += [_RULE, "The report could not be read; nothing is summarised."]
    else:
        if not ins.content_trusted:
            lines += [_RULE, "WARNING: this bundle FAILED verification. The values below are shown for diagnosis only and must not be relied on."]
        env = s["environment"]
        lines += [_RULE, f"Run           : {_t(s['run_id'])}", f"Started       : {_t(s['started_at'])}   Finished: {_t(s['finished_at'])}",
                  f"Environment   : os {_t(env.get('os'))}, arch {_t(env.get('arch'))}, python {_t(env.get('python'))}",
                  f"Plan digest   : {_t(s['plan_digest'])}"]
        if s["tools"]:
            lines.append("Tools         : " + ", ".join(f"{_t(k)} {_t(val)}" for k, val in sorted(s["tools"].items())))
        lines += [_RULE, "NATIVE ENGINE RESULTS (what each engine itself reported; not verdicts)"]
        for lane in s["lanes"]:
            n = lane["native"]
            lines.append(f"  lane {_t(lane['lane_id'])} run {_t(lane['run_id'])}: {_t(lane['engine']['name'])} {_t(lane['engine']['version'])}  "
                         f"native={n['status']} (engine said {_t(n['raw_status'], 64)!r}) exit={n['exit_code']} artifacts={len(n['artifacts'])}")
            for a in n["artifacts"]:
                lines.append(f"      {_t(a['path'])}  {a['digest']}  {a['size']} bytes")
        iv = s["independent_verdict"]
        prov = iv["provenance"]
        lines += [_RULE, "INDEPENDENT VERDICT (verifier over recorded observations and frozen assertions)" if verdicts_recomputed
                  else "VERDICT AS RECORDED (the runner's own; not recomputed by this command)",
                  f"  outcome      : {iv['outcome']} ({_t(iv['reason_code'])})",
                  f"  verifier     : {_t(prov['verifier']['id'])} {_t(prov['verifier']['version'])}",
                  f"  assertion set: {prov['assertion_set_digest']}", f"  evidence set : {prov['evidence_set_digest']}"]
        a = s["accounting"]
        lines.append(f"  accounting   : frozen {a['frozen']} = verified {a['verified']} + failed {a['failed']} + inconclusive {a['inconclusive']} + unaccounted {a['unaccounted']}")
        for lane in s["lanes"]:
            c = lane["independent_verdicts"]
            lines.append(f"  lane {_t(lane['lane_id'])}: verified {c['VERIFIED']}, failed {c['FAILED']}, inconclusive {c['INCONCLUSIVE']}, unaccounted {c['UNACCOUNTED']}")
        for d in s["engine_verifier_disagreements"]:
            lines.append(f"  ENGINE_VERIFIER_DISAGREE lane {_t(d['lane_id'])}: native {d['native_status']}, verdicts {', '.join(d['verdict_states'])}")
        lines += [_RULE, "ASSERTIONS"]
        for r in s["assertions"]:
            vd = r["verdict"]
            ev = vd["provenance"]["evidence"] if vd["provenance"] else None
            lines.append(f"  {_t(r['assertion_id'])} [{_t(r['lane_id'])}] native={r['native_status']} verdict={vd['state']} ({_t(vd['reason_code'])})"
                         + (f" evidence={_t(ev['path'])} {ev['digest']}" if ev else ""))
        red = s["redaction"]
        lines += [_RULE, f"Redaction     : applied={red['applied']}"]
        for rule in red["rules"]:
            lines.append(f"  rule {_t(rule['id'])}: {_t(rule['description'])} ({rule['count']})")
        for note in red["notes"]:
            lines.append(f"  note: {_t(note)}")
        lines += [_RULE, "LIMITATIONS"]
        for lim in s["limitations"]:
            lines.append(f"  - {_t(lim['id'])}: {_t(lim['text'], 2000)}")
    if v.findings:
        lines += [_RULE, "FINDINGS"]
        for f in v.findings:
            lines.append(f"  {f.code}  {_t(f.path)}  {_t(f.message)}")
    if v.informational or v.notes:
        lines += [_RULE, "INFORMATIONAL (tolerated, never used for a decision)"]
        for i in v.informational:
            lines.append(f"  field {i['document']}{_t(i['pointer'])}")
        for n in v.notes:
            lines.append(f"  {n['code']} ({n['document']}): {_t(n['message'])}")
    if verdicts_recomputed:
        lines += [_RULE, "Verified means the assertions were evaluated by an independent verifier over recorded observations; it does not mean the", "application under test is correct.", ""]
    else:
        lines += [_RULE, NOT_RECOMPUTED_CLOSING, ""]
    return "\n".join(lines)


_STYLE = """
body{font:14px/1.45 system-ui,sans-serif;margin:1.5rem auto;max-width:72rem;padding:0 1rem;color:#1a1a1a;background:#fff}
h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:1.6rem;border-bottom:1px solid #bbb;padding-bottom:.2rem}
table{border-collapse:collapse;width:100%;margin:.4rem 0}th,td{border:1px solid #bbb;padding:.25rem .5rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#f0f0f0}code{font-family:ui-monospace,monospace;font-size:.9em;overflow-wrap:anywhere}
p,li,.banner{overflow-wrap:anywhere}
.banner{padding:.7rem 1rem;border:2px solid;margin:.6rem 0;font-weight:600}
.ok{border-color:#2d6a2d;background:#eef7ee}.warn{border-color:#9a6700;background:#fff6dd}.bad{border-color:#a11;background:#fdeaea}
.native{background:#eef3fb}.verdict{background:#f3eefb}.small{font-size:.9em;color:#444}
"""


def render_html(ins: Inspection, *, verdicts_recomputed: bool = True) -> str:
    e = lambda value, limit=2000: html.escape(safe_text(value, limit), quote=True)      # noqa: E731
    v = ins.verification
    out: List[str] = ["<!DOCTYPE html>", '<html lang="en"><head><meta charset="utf-8">',
                      '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
                      '<meta name="viewport" content="width=device-width,initial-scale=1">']
    s = ins.summary
    out.append("<title>QA evidence bundle%s</title><style>%s</style></head><body>" % (" - " + e(s["run_id"]) if s else "", _STYLE))
    out.append("<h1>QA evidence bundle</h1>")
    vclass = ("ok" if verdicts_recomputed else "warn") if v.ok else "bad"
    out.append('<div class="banner %s">Verification: %s</div>' % (vclass, ("OK - internally consistent" if verdicts_recomputed else e(NOT_RECOMPUTED_OK)) if v.ok else "FAILED - %d finding(s)" % len(v.findings)))
    aclass = "ok" if v.anchor.matches else ("bad" if v.anchor.state in ("mismatch", "invalid") else "warn")
    out.append('<div class="banner %s">External anchor: %s</div>' % (aclass, e(v.anchor.notice)))
    if v.plan is not None:
        pclass = "ok" if v.plan.matches else ("bad" if v.plan.state in ("mismatch", "invalid") else "warn")
        out.append('<div class="banner %s">Frozen assertion set: %s</div>' % (pclass, e(v.plan.notice)))
    out.append('<p class="small">Anchor state: <code>%s</code>%s. Manifest digest: <code>%s</code>. Form: %s, %d file(s).</p>' % (
        e(v.anchor.state), (" (type %s, reference %s)" % (e(v.anchor.anchor_type), e(v.anchor.reference))) if v.anchor.anchor_type else "",
        e(v.manifest_digest), e(v.form), v.file_count))
    if s is None:
        out.append("<p>The report could not be read; nothing is summarised.</p>")
    else:
        if not ins.content_trusted:
            out.append('<div class="banner bad">This bundle FAILED verification. The values below are shown for diagnosis only and must not be relied on.</div>')
        env = s["environment"]
        out.append("<h2>Run</h2><table><tr><th>Run id</th><td>%s</td></tr><tr><th>Started / finished</th><td>%s / %s</td></tr>"
                   "<tr><th>Environment</th><td>os %s, arch %s, python %s</td></tr><tr><th>Plan digest</th><td><code>%s</code></td></tr>" % (
                       e(s["run_id"]), e(s["started_at"]), e(s["finished_at"]), e(env.get("os")), e(env.get("arch")), e(env.get("python")), e(s["plan_digest"])))
        if s["tools"]:
            out.append("<tr><th>Tools</th><td>%s</td></tr>" % ", ".join("%s %s" % (e(k), e(val)) for k, val in sorted(s["tools"].items())))
        out.append("</table>")
        out.append('<h2>Native engine results</h2><p class="small">What each engine itself reported. These are not verdicts.</p>'
                   '<table class="native"><tr><th>Lane</th><th>Run id</th><th>Engine</th><th>Native status</th><th>Engine said</th><th>Exit</th><th>Artifacts</th></tr>')
        for lane in s["lanes"]:
            n = lane["native"]
            arts = "<br>".join("<code>%s</code> %s (%d bytes)" % (e(a["path"]), e(a["digest"]), a["size"]) for a in n["artifacts"]) or "none"
            out.append("<tr><td>%s</td><td>%s</td><td>%s %s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                e(lane["lane_id"]), e(lane["run_id"]), e(lane["engine"]["name"]), e(lane["engine"]["version"]), e(n["status"]), e(n["raw_status"]), e(n["exit_code"]), arts))
        out.append("</table>")
        iv = s["independent_verdict"]
        prov = iv["provenance"]
        out.append('<h2>%s</h2><p class="small">%s</p>'
                   '<table class="verdict"><tr><th>Outcome</th><td><strong>%s</strong> (%s)</td></tr><tr><th>Verifier</th><td>%s %s</td></tr>'
                   '<tr><th>Assertion set digest</th><td><code>%s</code></td></tr><tr><th>Evidence set digest</th><td><code>%s</code></td></tr>' % (
                       "Independent verdict" if verdicts_recomputed else "Verdict as recorded",
                       "Produced by a verifier over recorded observations and frozen assertions, with its provenance." if verdicts_recomputed
                       else "The runner's own verdict, as recorded in the bundle; no command recomputed it here.",
                       e(iv["outcome"]), e(iv["reason_code"]), e(prov["verifier"]["id"]), e(prov["verifier"]["version"]),
                       e(prov["assertion_set_digest"]), e(prov["evidence_set_digest"])))
        a = s["accounting"]
        out.append("<tr><th>Accounting</th><td>frozen %d = verified %d + failed %d + inconclusive %d + unaccounted %d</td></tr></table>" % (
            a["frozen"], a["verified"], a["failed"], a["inconclusive"], a["unaccounted"]))
        out.append('<table class="verdict"><tr><th>Lane</th><th>Verified</th><th>Failed</th><th>Inconclusive</th><th>Unaccounted</th></tr>')
        for lane in s["lanes"]:
            c = lane["independent_verdicts"]
            out.append("<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td></tr>" % (e(lane["lane_id"]), c["VERIFIED"], c["FAILED"], c["INCONCLUSIVE"], c["UNACCOUNTED"]))
        out.append("</table>")
        for d in s["engine_verifier_disagreements"]:
            out.append('<div class="banner warn">ENGINE_VERIFIER_DISAGREE: lane %s, native %s, verdicts %s</div>' % (e(d["lane_id"]), e(d["native_status"]), e(", ".join(d["verdict_states"]))))
        out.append("<h2>Assertions</h2><table><tr><th>Assertion</th><th>Lane</th><th>Native status</th><th>Verdict</th><th>Reason</th><th>Evidence</th></tr>")
        for r in s["assertions"]:
            vd = r["verdict"]
            ev = vd["provenance"]["evidence"] if vd["provenance"] else None
            out.append("<tr><td>%s</td><td>%s</td><td class=\"native\">%s</td><td class=\"verdict\">%s</td><td>%s</td><td>%s</td></tr>" % (
                e(r["assertion_id"]), e(r["lane_id"]), e(r["native_status"]), e(vd["state"]), e(vd["reason_code"]),
                ("<code>%s</code> %s" % (e(ev["path"]), e(ev["digest"]))) if ev else "none"))
        out.append("</table>")
        red = s["redaction"]
        out.append("<h2>Redaction</h2><p>Applied: %s</p><ul>%s%s</ul>" % (e(red["applied"]), "".join("<li>rule %s: %s (%d)</li>" % (e(x["id"]), e(x["description"]), x["count"]) for x in red["rules"]),
                                                                       "".join("<li>%s</li>" % e(x) for x in red["notes"])))
        out.append("<h2>Limitations</h2><ul>%s</ul>" % "".join("<li><strong>%s</strong>: %s</li>" % (e(x["id"]), e(x["text"])) for x in s["limitations"]))
    if v.findings:
        out.append('<h2>Findings</h2><table class="bad"><tr><th>Code</th><th>Where</th><th>Message</th></tr>%s</table>' % "".join(
            "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (e(f.code), e(f.path), e(f.message)) for f in v.findings))
    if v.informational or v.notes:
        out.append("<h2>Informational</h2><p class=\"small\">Tolerated; never used for a decision.</p><ul>%s%s</ul>" % (
            "".join("<li>field %s%s</li>" % (e(i["document"]), e(i["pointer"])) for i in v.informational),
            "".join("<li>%s (%s): %s</li>" % (e(n["code"]), e(n["document"]), e(n["message"])) for n in v.notes)))
    if ins.files:
        out.append("<h2>Files</h2><table><tr><th>Path</th><th>Role</th><th>Size</th><th>sha256</th></tr>%s</table>" % "".join(
            "<tr><td>%s</td><td>%s</td><td>%d</td><td><code>%s</code></td></tr>" % (e(f["path"]), e(f["role"]), f["size"], e(f["digest"])) for f in ins.files))
    out.append('<p class="small">%s</p>' % ("Verified means the assertions were evaluated by an independent verifier over recorded observations; it does not mean the application under test is correct."
                                          if verdicts_recomputed else e(NOT_RECOMPUTED_CLOSING)))
    out.append("</body></html>")
    return "\n".join(out) + "\n"
