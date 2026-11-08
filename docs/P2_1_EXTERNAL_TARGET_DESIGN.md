# P2-1 — pointing the engine at an external target: technical design

**Status: design and acceptance criteria only. Nothing here is implemented, and no Projects QA tab is implied.**
Written as the prerequisite the UI/QA external-reuse plan assumes exists: until this ships, `run` and `demo`
drive the bundled fixture app and nothing else, and that must stay the stated claim. Licence: source-available
under the family licence (AGPL-3.0-or-later with the Commons Clause), not open source.

Everything marked *verified* below was read out of this repository at `main@7111021`, not assumed.

## 1. What exists today (verified)

| Fact | Where |
|---|---|
| A plan's target is exactly `{"kind": "fixture-app"}`; any other shape or kind is `BAD_TARGET` | `packages/qa-runner/src/qa_runner/plan.py:146` (`set(target) != {"kind"}`; `TARGET_KINDS = ("fixture-app",)` at `:53`) |
| The runner starts the target itself, on a fresh port, and recomputes the executed spec from the template and the recorded origin | `plan.py:14` |
| Every lane names an egress profile; Playwright has one option, Robot may also be `not-enforced` | `EGRESS_PROFILES`, `plan.py:52` |
| A gateway exists that resolves once per decision, refuses what is not allowed, and **connects only to the address the decision pinned** | `packages/qa-egress/src/qa_egress/gateway.py:6` |
| Operator policy form `{"allow": [...], "private": [{host, networks, schemes, ports}], "max_redirects": n}` plus `limits.max_response_bytes`; the config file is "the operator owns (never a page, a spec or a model output)" | `packages/qa-egress/src/qa_egress/__main__.py:5-13` |
| The runner already builds that policy from a profile and an origin | `packages/qa-runner/src/qa_runner/egress.py:13` (`policy_config(profile, origin)`) |
| `--defect` is a `choices=` over the fixture app's seeded defects, so the CLI itself cannot express another target | `packages/qa-runner/src/qa_runner/cli.py:65` |
| The independent probe is `qa_fixture_app.reference_check`, which restates the seed data and the rule on its own over plain HTTP | `orchestrate.py:376-378` |
| Platform claim: CPython 3.12 (fixture-app CI also 3.11), Linux x86_64 only | `README.md:9` |

The engine is therefore not fixture-only by accident. Fixture-only is enforced in the plan schema, the CLI
argument, the origin derivation and the independent probe — four places, and P2-1 has to satisfy all four
rather than relax any of them.

## 2. The problem P2-1 actually has to solve

Naming a URL is the easy half. The engine's current authority to print **VERIFIED** comes from having started
the target itself and holding an independent restatement of its expected data (`reference_check`). Hand it
`https://app.example` and three things break at once:

1. **Origin honesty.** The plan no longer knows which process answers; an operator-supplied string becomes the
   definition of "the thing under test", which is exactly the kind of claim this repository refuses to take
   from configuration.
2. **Independence.** There is no seed data to restate, so no second source can back an assertion. A verdict
   against an external target is corroborated by the engines only, and the bundle must say so.
3. **Blast radius.** A run against a real deployment can mutate it. The fixture app exists precisely because
   mutating it is safe.

So P2-1 is a trust-boundary feature, not a `--url` flag. Its deliverable is a target the engine can describe
honestly, reach through a pinned gateway, and refuse to over-claim about.

## 3. Proposed contract

### 3.1 Target kinds

```python
TARGET_KINDS = ("fixture-app", "external-origin")
```

`fixture-app` keeps its current meaning and its current shape. A new target carries:

```json
{"kind": "external-origin",
 "origin": "https://app.example",
 "declared_by": "operator",
 "credential_refs": ["env:QA_EXAMPLE_TOKEN"],
 "mutating": false}
```

Rules, each mechanically checkable at `check`/`freeze` time:

- **`origin` is an origin, not a URL**: scheme + host + port only. A path, query, fragment, userinfo or
  trailing slash is refused. `http` is refused unless the origin is loopback, or the operator has declared
  cleartext for it in the egress policy — which is where cleartext already has to be declared.
- **`declared_by` is always `operator`.** A plan generated from a page, a ticket or a model answer is not a
  target declaration; the field exists so a bundle read later shows where the target came from.
- **`credential_refs` are references, never values** — `env:NAME`, or a `file:` path outside the bundle. A
  literal token, a URL carrying userinfo, or a key-shaped string is a hard rejection. This matches the
  repository's existing posture: the egress config is operator-owned, and the secret-scan workflow guards
  history against leaks.
- **`mutating: false` is the default and the only supported value at first.** A run that may write to a real
  system is a different feature with an approval story; folding it into P2-1 would make "read-only QA" a
  claim rather than a guarantee.

### 3.2 The origin *is* the egress scope

Reuse, do not invent: the lane's `egress` profile plus `policy_config(profile, origin)` already produces the
`{"allow": [...], "private": [...]}` shape. For an external target the allowed set becomes exactly the
declared origin, and the gateway keeps its existing guarantee — resolve once, refuse what is not allowed,
connect only to the pinned address, and do not follow a redirect into a different origin. Redirect handling
is already modelled (`_Redirects`, `gateway.py:99`), which is why this is the right seam: **no new allowlist
syntax, and no second implementation of "where am I allowed to go".**

Required consequence, stated so it cannot be quietly dropped: a lane whose engine is Robot and whose profile
is `not-enforced` **cannot** target an external origin. That profile exists because the fixture app is
harmless; against a real deployment there is no honest verdict to print if the socket was never constrained.
`BAD_EGRESS_FOR_TARGET` at `check` time, not a warning at run time.

### 3.3 What freeze, run and the bundle must record

`freeze` records the origin, the resolved policy digest and the credential **reference** set (never values).
`run` records, per lane, the address actually connected to and whether it matched the pin. And the bundle's
verification level for an external target is capped: **`CORROBORATED`, never `VERIFIED`**, because the
independent restatement that backs `VERIFIED` today (`reference_check`) has no counterpart for an arbitrary
deployment. The cap belongs in the code that computes the level, not in prose.

### 3.4 `estimate` (the dry run)

`redevops-qa estimate PLAN` prints, as JSON, without contacting anything and without writing a bundle:

- the origin, the resolved egress policy and its digest, the engines and pinned browsers that would run;
- the lane deadlines, the byte and hop limits that would apply, the credential references that would be
  resolved (names only);
- every problem that will make the run refuse, in the same words `run` will use.

It exists so "what would this do to production?" is answerable before answering it. It is a plan-time check
built on the same validator as `run`, not a parallel description that can drift from it.

## 4. Acceptance criteria

The executable subset is `tests/test_p21_external_target_acceptance.py`: today's guarantees are pinned green,
and each future criterion exists as a named guard that fails the moment it becomes implementable, so the
documentation cannot silently outrun the code.

| ID | Given / When / Then | Lands in |
|---|---|---|
| AC-1 | Given a plan with `target.kind = "fixture-app"` → `check`/`run` behave exactly as today, identical plan digest | regression |
| AC-2 | Given `{"kind": "external-origin", "origin": "https://app.example"}` → `check` accepts it, and `run` no longer starts the fixture app for it | validator, orchestrate |
| AC-3 | Given an `origin` carrying a path, userinfo or any non-origin form → rejected, naming the field | validator |
| AC-4 | Given a literal secret (e.g. `credential_refs: ["Bearer abcd…"]`) → rejected; given `env:NAME` → the name is recorded and the value appears nowhere in plan, lock, bundle or logs | validator, bundle |
| AC-5 | Given a Robot lane on `not-enforced` against an external origin → rejected at `check` | validator |
| AC-6 | Given the origin answers with a public address while the policy declares a private range → the lane refuses, and the refusal is in the bundle with its reason | gateway |
| AC-7 | Given a redirect from the origin to a host outside the policy → refused, and the attempt recorded | gateway |
| AC-8 | Given a DNS answer that changes between decision and connect → the connection uses the pinned address, or refuses | gateway |
| AC-9 | Given a successful external run → bundle level is `CORROBORATED`, and the bundle states that no independent restatement backed the assertions | level computation |
| AC-10 | Given `estimate` on any plan → exit 0, no outbound connection attempted (asserted by tripwire), no bundle written, output agrees with `check` | CLI |
| AC-11 | Given `mutating: true` → refused at this stage, with a message naming the approval design it waits on | validator |
| AC-12 | Given any external-target evidence → the platform claim (Linux x86_64, CPython 3.12/3.11) is stated in the bundle, and a non-Linux host refuses rather than degrades | runner |

## 5. Deliberately out of scope

- Any write/mutating QA against a real system, and any approval workflow for it (AC-11 keeps that door shut).
- A Projects QA tab, or any UI: the interface this design exposes is a CLI and a bundle.
- Broadening platforms, engines or the browser pin set.
- Windows/macOS lanes, and anything that lets the README's fixture-only sentence be softened before
  AC-1…AC-12 are green on Linux CI.

## 6. Open questions for the owner

1. **Credential resolution point.** Resolve `env:NAME` in the runner process (simplest; the value then lives
   in the runner's memory) or in the gateway (better isolation: the browser never holds it, and it belongs
   with the pinned-connection design). Recommendation: gateway.
2. **First external target.** The Edge Sentinel dashboard is the obvious candidate — it now has a read-only
   fixture mode that is safe to point a QA run at (`EDGE_SENTINEL_DEMO=1`, loopback, refuses every CrowdSec
   side effect), which makes it a low-risk first consumer while still being a real deployment rather than a
   test double.
3. **Verification cap.** Is `CORROBORATED` the right ceiling without an independent restatement, or should an
   external target reach `VERIFIED` when an operator-supplied expected-value file is frozen into the lock?
   Recommendation: keep the cap; treat a frozen expectation file as a later feature with its own trust rules.
4. **Plan provenance.** Does `declared_by` need a signature (the repository already has signing machinery in
   `anchor_sig.py`), or is an operator-stated field plus the bundle's own digest sufficient for now?

## 7. Sequencing and sizing

Rough, for sequencing only, one engineer familiar with the repo:

1. **Slice 1** — validator + CLI surface for `external-origin` (AC-2…AC-5, AC-11) with the AC-1 regression
   guard. Smallest slice, no runtime risk, everything it rejects is visible at `check`.
2. **Slice 2** — gateway criteria (AC-6…AC-8). Largely *tests* against machinery that already exists
   (`qa-egress` pinning and redirects), which is the argument for reusing it rather than writing a second
   client.
3. **Slice 3** — bundle and level changes (AC-9). Small code, but it touches the claim vocabulary, so it
   wants review.
4. **Slice 4** — `estimate` (AC-10), new CLI surface over existing validation, plus AC-12's platform guard.

Nothing here needs a new engine, and nothing here should be built as a UI.


