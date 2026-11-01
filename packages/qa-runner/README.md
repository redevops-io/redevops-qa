# qa-runner

The `redevops-qa` command: it checks a machine (`doctor`), freezes a test plan (`freeze`), runs a frozen plan against the fixture app and writes an evidence bundle (`run`),
re-verifies a finished run from its bundle alone (`verify`), reports and inspects a bundle (`report`, `inspect`) and does all of that in one step for the built-in two-lane plan (`demo`).
A plan holds a Playwright Chromium lane (`examples/golden-plan.json`), a Robot Framework lane (`examples/robot-plan.json`) or both, run one after the other
(`examples/demo-plan.json`).

Licence: the family licence of this repository (source-available, not open source; see `LICENSE.md`). Standard library and the repository's own packages
only; the two pinned upstreams (`runtime-contracts`, `agent-harness`) are found through `pins.toml`, as the bridge does it, and are neither installed nor
copied.

Scope of this release line: Linux x86_64, Playwright Chromium and Robot Framework. macOS runs are development evidence only (`doctor` says so). Selenium and
Appium are not part of this workflow. Nothing here has been run on any other platform.

## Commands

```text
redevops-qa doctor [--plan PLAN] [--json]
redevops-qa freeze PLAN --out LOCK
redevops-qa run PLAN_OR_LOCK --out DIR [--defect none|discount|settings] [--run-id ID] [--lane-deadline SECONDS]
redevops-qa verify BUNDLE [--anchor sha256:HEX] [--plan-digest sha256:HEX] [--require-anchor] [--require-plan-digest] [--json]
redevops-qa demo [--out DIR] [--defect none|discount|settings] [--run-id ID] [--lane-deadline SECONDS]
redevops-qa report BUNDLE [--format text|json|html] [-o FILE] [--anchor sha256:HEX] [--plan-digest sha256:HEX]
redevops-qa inspect BUNDLE [--anchor sha256:HEX] [--plan-digest sha256:HEX]
```

`python -m qa_runner ...` is the same command from a checkout (`PYTHONPATH` set to the `src` directories of the packages; the tests and the CI job show how).

**`doctor`** reports Python, platform, the temporary directory, the pinned dependencies (commits, tree digests and vector files against `pins.toml`),
Playwright 1.64.1 and a real headless Chromium launch, Robot Framework 7.5, the fixture app and the egress gateway. Each check is `OK`, `WARN` (works, outside
what this release claims: any platform but Linux x86_64) or `FAIL`, with the command that fixes it. It never installs, downloads or changes anything. A
protection that cannot be provided is a `FAIL`: the egress gateway that every browser lane depends on must start. Exit status 0, or 3 if a check failed.

**`freeze`** validates a plan (the strict runtime-contracts parser first, then the harness mirror; unknown fields refused at every level), computes every assertion's digest, the
assertion lock and the plan digest, and writes the lock (`redevops-qa/plan-lock` 1.0: the plan, the digests, the pins, the suite file hashes). A lock is never overwritten. The plan
digest it prints is what `verify --plan-digest` will compare a bundle with; record it where whoever runs the plan cannot rewrite it (without it a removed assertion would not be
noticed). `run` accepts a plan (frozen on the spot, with a note on standard error) or a lock; a lock is re-frozen from the plan it carries and refused if any digest, pin, tool version,
suite hash or expected value differs.

**`demo`** is `freeze` and `run` on the built-in plan (browser lane, then Robot lane, one target, one run id) followed by the full report. It prints no plan digest comparison: a digest
computed by the process that ran the plan would only match itself.

**`report`** and **`inspect`** read a bundle (directory or archive) through `qa-evidence`: they verify it first, never recompute a verdict, escape every string that came from the
bundle, and exit 0 only if the bundle verified as internally consistent (1 if not, 2 if it cannot be opened). `report` renders text, JSON or one HTML file with no script and a
content-security policy; `inspect` lists the files with roles and digests, the tool versions, the lanes and the heads of the chains inside each harness run record.

**`verify`** re-verifies a finished run from its bundle alone, offline, in a process of its own (see "What verification does and does not prove" below). Exit status: for an accepted bundle
the same table as `run` (0 VERIFIED, 1 FAILED, 3 a lane did not complete, 4 inconclusive); **5 when any finding rejects the evidence**; 2 when the bundle cannot be opened. `run` and
`demo` end by calling `verify` in a separate interpreter (fresh environment, no state shared) and exit 5 if it does not accept what they just wrote.

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
| 5 | `verify` rejected the evidence (any finding), including the verification a run does of its own bundle |
| 6 | an internal error of the runner (a crash is never reported as a product failure) |

## The plan

A plan (`redevops-qa/plan` 1.0, see `examples/`) names lanes; a lane carries a runtime-contracts `qa/v1` `TestSpec` whose assertions hold the
expected values. Freezing:

* refuses a plan or lane field it does not know, and a spec field the **runtime-contracts parser** does not know. The parser runs before the harness
  mirror because the mirror tolerates unknown spec fields and they change the spec hash (`tests/test_qr_plan.py` shows both);
* gives every assertion a digest (sha256 of its canonical JSON, expected value included), computes the assertion lock and the plan digest with the
  conventions of `qa-evidence`, and requires the contracts and the harness to agree on the assertion-set pin;
* refuses an assertion id that appears in two lanes (every assertion is accounted exactly once).

A step value may start with `{origin}`; the origin of this start of the target is substituted when the lane runs, so one frozen plan serves every start of
the app (a different port each time).

## The Robot lane

A Robot lane names a reviewed suite shipped with this package (`"suite": "order-discount"`: `src/qa_runner/robot_suite/order_discount.robot` and the library `OrderApi.py`).
Freezing hashes the suite files and the registered check program into the lock; the run copies the files into a fresh workspace, requires the copies to hash as frozen, and
gives the Robot adapter the library's hash as the only reviewed library (the adapter refuses any other library file, any library not on its allowlist and any construct that
loads code at run time). The suite runs under the kit supervisor with `QA_BASE_URL` as the only variable it is given.

* **Robot records, the verifier judges.** The suite reads the order totals from the target's API and records them as `qa-observe:<name>=<value>` tags; its own
  `Should Be Equal` lines are the engine's native check. The runner keeps the raw `output.xml` as a native artifact and derives the observation record from it
  (`qa_robot.parse_observations`). The frozen assertion (`executor = SCRIPT`, `EQUALS`) holds the expected values and pins the hash of the check program
  `evidence.robot-observations`; the harness `DeterministicVerifier` runs that program (through the `qa-checks` adapter, over a case root that holds the record and nothing else)
  and compares its observation with the frozen value. The program is never given the expected value and the record carries none.
* **Native result and verdict stay apart.** `NATIVE_PASS`/`NATIVE_FAIL` is what Robot said; the verdict is the comparison. A native PASS with a record that does not satisfy the
  frozen assertion is not VERIFIED; a native FAIL whose record satisfies it is INCONCLUSIVE (`NATIVE_FAIL_VERIFIED_ASSERTIONS`).
* **The record must be what the importer derives from the engine's own report that is in the bundle** (same run id, same lane, same digest of `output.xml`, canonical bytes): a
  hand-written record, one from another run or one that does not belong to the report next to it is unusable evidence (`EVIDENCE_UNUSABLE`).
* **Egress is not enforced for a Robot lane.** A Robot library opens its own sockets. The lane's egress profile says `not-enforced` and the plan must say so (`"egress": "not-enforced"`;
  a browser lane must use `origin-only`).
* **Same supervision as the browser lane:** the Robot lane runs in a child process too (the same deadline, cancel, process-group kill, and a parent-death watchdog), and the engine runs
  under its own supervisor inside it.
* **Not detectable from the record:** a suite that records a value it did not observe. What protects against that is the review of the suite and library (their hashes are frozen and
  checked before the run, and the copies are in the bundle) and the target's request log (`logs/target-requests.jsonl`), not the record.

## What a run does

1. The fixture app starts as a child process (`--shutdown-on-stdin-eof`, its own process group) and is stopped in a `finally` block. One target serves every lane.
2. Lanes run one after the other, in plan order, under one run id (lane run ids are `<run id>.<lane id>`). A lane that fails, times out or crashes does not stop the next one: its
   result is recorded and the next lane still runs, so a run always accounts for every frozen assertion of every lane exactly once. After a cancel the remaining lanes are
   recorded as `NATIVE_SKIPPED`.
3. Each lane runs as a child process under the kit supervisor: a deadline, an output limit and cancellation end the whole process group, the browser (or the Robot process)
   included. SIGINT and SIGTERM to `redevops-qa` cancel the run: the lane is ended, the remaining lanes are skipped, the target is stopped, a bundle with outcome `INCONCLUSIVE` is
   still written and the exit status is 3. If the orchestrator is killed without warning (SIGKILL), each lane child notices that its parent is gone within a fraction of a second
   and ends its own process group (and, for the Robot lane, the engine it started); the target ends when its standard input closes. The end-to-end tests check, with a process
   table, that no process survives a cancel and a SIGKILL of the parent, and fail when the watchdog is removed. The environment of a child is built from nothing (fixed `PATH` and `HOME`; the import path, the pins and the browser location are passed
   explicitly; no other variable of the parent).
4. The browser lane wires the harness executor (`QARunner`) to the real `PlaywrightAdapter` over real Chromium, with the egress gateway in front of the
   browser and the adapter's request gate behind it, an action policy that allows only the plan's origin, and attestations answered from facts (the
   target's `/health`; declared preconditions or fixtures that nothing can attest are *unknown*, which blocks a pass).
5. Everything the lane wrote is collected as native artifacts. The observed values the harness verifier read are recorded in an observation file.
6. The verdicts are computed by `judge_lane` over the observation file and the frozen assertions, using the harness `DeterministicVerifier`. The in-run
   verifier's verdicts are a cross-check: a disagreement certifies nothing.
7. The bundle is built by a pure function (`bundle.build_run_bundle`, no clock, no environment, no file system) with `qa-evidence`, which checks its own output.

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
lanes/robot/native/output.xml          the Robot engine's own report; also robot-summary.json and adapter-result.json (native)
lanes/robot/observations.json          the observation record derived from output.xml: what the check program reads (observation)
lanes/robot/suite/*                    the reviewed suite files the engine ran, as hashed in the lock (record)
lanes/robot/egress-profile.json        says that egress is not enforced for this lane (record)
logs/                                  orchestration log, tails of the lane output, the target's request log (log)
```

Plus the files `qa-evidence` writes: `report.json`, `bundle-manifest.json`, `assertion-lock.json`, `BUNDLE-FORMAT.txt`.

## What verification does and does not prove

`redevops-qa verify BUNDLE` (a directory or the canonical archive) reads nothing but the bundle, opens no socket and loads no browser, Robot Framework or HTTP client library of its own
(a test proves both). It re-computes, and reports a finding for any difference:

1. every file digest and size, the manifest and the report schema, the accounting (every frozen assertion exactly once), the lane ids and run ids, and the external anchor and plan digest if you
   supply them (`qa-evidence`);
2. the frozen plan: `plan.lock.json` is re-frozen with the pinned runtime-contracts and harness parsers (unknown fields refused) and must equal itself, the report's frozen set and the
   assertion lock, with every expected value, digest, assertion-set pin and check-program hash recomputed; the suite files in the bundle must be the ones the lock froze;
3. **every verdict**, from the files in the bundle: the recorded browser observations against the frozen assertions, and for the Robot lane the hash-pinned check program over a record that
   must be exactly what the importer derives from the engine's own `output.xml` in the bundle. A report that says something else is `VERDICT_RECOMPUTE_MISMATCH`;
4. each lane's **native status**, re-derived from the engine's own files (the harness outcome and exit code, the Robot adapter result and the test statuses of `output.xml`); a native FAIL
   written as a PASS is `NATIVE_STATUS_RELABELLED`; an engine status this verifier does not map is never read as a pass;
5. each browser lane's **harness run record**: the event and receipt chains, the manifest, the run id, the frozen assertion pin, the executed spec (rebuilt from the frozen template and the
   allowed origin), and that every observation equals what the record says was read.

An observation row or record that carries a field an adapter has no business writing (a verdict, a `verified` claim, an expected value) is unusable evidence: the assertion is `INCONCLUSIVE`.

What an accepted bundle means, and what it does not:

* **Without `--anchor`, accepted means INTERNALLY CONSISTENT, nothing more.** The hashes and the manifest are unkeyed. They detect accidental changes and partial edits. They do not detect a bundle
  that was rewritten consistently from start to finish by someone who can rewrite all of it: the product's own builder would produce the same bytes from forged inputs, and the tamper suite shows
  it (`tests/test_qr_tamper_suite.py`): the failing lane dropped, an assertion weakened, or the engine's own report rewritten to say the rule held, with every digest recomputed, is accepted as
  internally consistent and says so. Only a manifest digest obtained from a place the forger cannot write (`--anchor`; the CI artifact attestation planned for the release job publishes it) rejects
  those. `verify` never calls a match with a value you supplied proof that the value is trustworthy.
* **`--plan-digest` closes one gap and no other.** The plan digest printed by `freeze` (record it outside the bundle) rejects a bundle whose frozen assertion set was changed or reduced; it cannot
  reject a forgery that left the plan alone.
* **Two partial backstops that need no anchor:** an engine that said FAIL while every assertion verifies makes the run `INCONCLUSIVE` (`NATIVE_FAIL_VERIFIED_ASSERTIONS`), so weakening an assertion
  without also rewriting the engine's files does not give a VERIFIED run; and the harness run record's chains are checked against each other, so editing one event is a finding unless the forger rebuilds the chain.
* **It does not establish that the application is correct.** It shows that the frozen assertions hold (or fail) over the recorded observations, and that the bundle is what it says. It does not re-drive the
  browser or the application and it does not show that a suite recorded what it observed (the target's request log and the frozen suite hashes are the only evidence of that).
* **Not covered:** verification with other pinned versions of runtime-contracts or agent-harness than the ones that wrote the bundle is reported as a note (every digest is re-derived with the tools loaded
  here, and they must agree); a check program or reviewed suite changed since the run makes older bundles fail to verify, by design.

## What this does not show

* The hash chain and the bundle manifest are unkeyed. They detect accidental changes and partial edits, not deliberate re-forging by anyone who can rewrite the
  whole bundle; only a manifest digest published somewhere that party cannot write (an external anchor) changes that. This part prints the digests; it
  does not publish or attest them.
* A verified verdict says the frozen assertions hold over the recorded observations. It does not say the application is correct.
* The harness run record, the gateway log and the logs are not passed through the redactor (only browser artifacts are). Do not put a secret in a plan that
  is run for evidence.
* Egress: the gateway and the request gate are exercised against Chromium on the machines named in the tests. Nothing here claims that all traffic of every
  engine passes the gateway; Robot Framework lanes will not.
* The browser and Robot lanes have run on macOS arm64 (development) and in the CI jobs named in the pull requests; no other platform.

## Tests

```text
python -m pytest -q packages/qa-runner/tests                                   # offline: no browser; the lane child is a test double in fake_lane.py
python -m pytest -q -m browser packages/qa-runner/tests/browser                # real Chromium (Playwright 1.64.1 and a browser installed)
python -m pytest -q -m robot_real packages/qa-runner/tests/real                # real Robot Framework 7.5 (no browser needed)
python -m pytest -q -m e2e packages/qa-runner/tests/e2e                        # both real engines in one run, cancellation and a killed parent
```

The offline tests include a mutation suite (`test_qr_mutations.py`): each removes one guard from a copy of the source and requires a named test to fail. The
browser tests start the fixture app and the gateway and drive a real browser: clean target, each seeded defect, a forbidden navigation, a page that tries to reach
another origin, a deadline (and a check that no process of the lane's group is left), and the command line in a scrubbed environment.
