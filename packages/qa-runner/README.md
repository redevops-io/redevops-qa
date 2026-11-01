# qa-runner

The `redevops-qa` command: it checks a machine (`doctor`), runs a frozen test plan against the fixture app and writes an evidence bundle (`run`). The
remaining subcommands (`freeze`, `verify`, `report`, `inspect`, `demo`) and the Robot Framework lane come in the following parts of this work; this part
runs ONE Playwright Chromium lane.

Licence: the family licence of this repository (source-available, not open source; see `LICENSE.md`). Standard library and the repository's own packages
only; the two pinned upstreams (`runtime-contracts`, `agent-harness`) are found through `pins.toml`, as the bridge does it, and are neither installed nor
copied.

Scope of this release line: Linux x86_64, Playwright Chromium and Robot Framework. macOS runs are development evidence only (`doctor` says so). Selenium and
Appium are not part of this workflow. Nothing here has been run on any other platform.

## Commands

```text
redevops-qa doctor [--plan PLAN] [--json]
redevops-qa run PLAN_OR_LOCK --out DIR [--defect none|discount|settings] [--run-id ID] [--lane-deadline SECONDS]
```

`python -m qa_runner ...` is the same command from a checkout (`PYTHONPATH` set to the `src` directories of the packages; the tests and the CI job show how).

**`doctor`** reports Python, platform, the temporary directory, the pinned dependencies (commits, tree digests and vector files against `pins.toml`),
Playwright 1.64.1 and a real headless Chromium launch, Robot Framework 7.5, the fixture app and the egress gateway. Each check is `OK`, `WARN` (works, outside
what this release claims: any platform but Linux x86_64) or `FAIL`, with the command that fixes it. It never installs, downloads or changes anything. A
protection that cannot be provided is a `FAIL`: the egress gateway that every browser lane depends on must start. Exit status 0, or 3 if a check failed.

**`run`** freezes the plan (or reads a lock), starts the fixture app on loopback with the defect you name, runs each lane as a supervised child process, stops
the app, and writes the bundle to `DIR/<run id>` (a directory that must not exist). It prints the outcome, what each engine reported, what the independent
verdicts are, the plan digest (the value to give `verify --plan-digest`) and the manifest digest (the value an external anchor should hold).

| Exit | Meaning |
|---|---|
| 0 | the run is `VERIFIED`: every lane `NATIVE_PASS` and every frozen assertion verified |
| 1 | at least one frozen assertion `FAILED` |
| 2 | the plan, the lock or an option was refused before anything ran |
| 3 | a lane did not run to completion (error, timeout, cancelled, unavailable), or the environment cannot provide what the run needs |
| 4 | inconclusive: every lane completed but not every assertion is verified, or an engine and the verifier disagree (`NATIVE_FAIL_VERIFIED_ASSERTIONS`) |
| 6 | an internal error of the runner (a crash is never reported as a product failure) |

## The plan

A plan (`redevops-qa/plan` 1.0, see `examples/golden-plan.json`) names lanes; a lane carries a runtime-contracts `qa/v1` `TestSpec` whose assertions hold the
expected values. Freezing:

* refuses a plan or lane field it does not know, and a spec field the **runtime-contracts parser** does not know. The parser runs before the harness
  mirror because the mirror tolerates unknown spec fields and they change the spec hash (`tests/test_qr_plan.py` shows both);
* gives every assertion a digest (sha256 of its canonical JSON, expected value included), computes the assertion lock and the plan digest with the
  conventions of `qa-evidence`, and requires the contracts and the harness to agree on the assertion-set pin;
* refuses an assertion id that appears in two lanes (every assertion is accounted exactly once).

A step value may start with `{origin}`; the origin of this start of the target is substituted when the lane runs, so one frozen plan serves every start of
the app (a different port each time).

## What a run does

1. The fixture app starts as a child process (`--shutdown-on-stdin-eof`, its own process group) and is stopped in a `finally` block.
2. Each lane runs as a child process under the kit supervisor: a deadline, an output limit and cancellation end the whole process group, the browser
   included. The environment of a child is built from nothing (fixed `PATH` and `HOME`; the import path, the pins and the browser location are passed
   explicitly; no other variable of the parent).
3. The browser lane wires the harness executor (`QARunner`) to the real `PlaywrightAdapter` over real Chromium, with the egress gateway in front of the
   browser and the adapter's request gate behind it, an action policy that allows only the plan's origin, and attestations answered from facts (the
   target's `/health`; declared preconditions or fixtures that nothing can attest are *unknown*, which blocks a pass).
4. Everything the lane wrote is collected as native artifacts. The observed values the harness verifier read are recorded in an observation file.
5. The verdicts are computed by `judge_lane` over the observation file and the frozen assertions, using the harness `DeterministicVerifier`. The in-run
   verifier's verdicts are a cross-check: a disagreement certifies nothing.
6. The bundle is built by a pure function (`bundle.build_run_bundle`, no clock, no environment, no file system) with `qa-evidence`, which checks its own output.

Every lane and every frozen assertion is accounted for whatever happens. A lane that cannot start, times out, is cancelled or crashes is recorded with a
native status that says so; its assertions are `INCONCLUSIVE`; the run is never `VERIFIED`. The engine's own status (`lanes[].native`) and the verdict
(`accounting.results[].verdict`) are separate fields with disjoint vocabularies. For the browser lane the native status is the harness executor's outcome
(`PASS` becomes `NATIVE_PASS`, `PRODUCT_FAIL` becomes `NATIVE_FAIL`, anything else `NATIVE_ERROR` or `NATIVE_TIMEOUT`); it is never converted into a verdict.

## Bundle contents

```
plan.lock.json                         the frozen plan, its digests and the pins (record)
lanes/browser/native/run-record.json   the harness run record: manifest, event chain, receipts, classification (native)
lanes/browser/native/lane-result.json  what the lane child reported, including the in-run verdicts (native)
lanes/browser/native/blobs/<sha256>    artifacts captured by the browser, redacted by the harness redactor (native)
lanes/browser/observations.json        the observed values the verdicts are computed from (observation)
lanes/browser/egress-profile.json      the allow-list the lane ran under, as data (record)
lanes/browser/gateway-log.jsonl        decisions of the egress gateway: scheme, host, port, verdict; no path, query or header (log)
lanes/browser/browser-guard-log.jsonl  decisions of the adapter's in-browser request gate, the second layer (log)
logs/                                  orchestration log, tails of the lane output, the target's request log (log)
```

Plus the files `qa-evidence` writes: `report.json`, `bundle-manifest.json`, `assertion-lock.json`, `BUNDLE-FORMAT.txt`.

## What this does not show

* The hash chain and the bundle manifest are unkeyed. They detect accidental changes and partial edits, not deliberate re-forging by anyone who can rewrite the
  whole bundle; only a manifest digest published somewhere that party cannot write (an external anchor) changes that. This part prints the digests; it
  does not publish or attest them.
* A verified verdict says the frozen assertions hold over the recorded observations. It does not say the application is correct.
* The harness run record, the gateway log and the logs are not passed through the redactor (only browser artifacts are). Do not put a secret in a plan that
  is run for evidence.
* Egress: the gateway and the request gate are exercised against Chromium on the machines named in the tests. Nothing here claims that all traffic of every
  engine passes the gateway; Robot Framework lanes will not.
* The browser lane has run on macOS arm64 (development) and in the CI job named in the pull request; no other platform.

## Tests

```text
python -m pytest -q packages/qa-runner/tests                                   # offline: no browser; the lane child is a test double in fake_lane.py
python -m pytest -q -m browser packages/qa-runner/tests/browser                # real Chromium (Playwright 1.64.1 and a browser installed)
```

The offline tests include a mutation suite (`test_qr_mutations.py`): each removes one guard from a copy of the source and requires a named test to fail. The
browser tests start the fixture app and the gateway and drive a real browser: clean target, each seeded defect, a forbidden navigation, a page that tries to reach
another origin, a deadline (and a check that no process of the lane's group is left), and the command line in a scrubbed environment.
