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
the app, and writes the bundle to `DIR/<run id>` (a directory that must not exist; it is reserved before anything runs and the bundle is renamed into place, so a reader sees no bundle or a whole one). It prints the outcome, what each engine reported, what the independent
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
* gives every assertion a digest (sha256 of its canonical JSON, expected value included) together with a binding to everything else that defines the lane: the
  whole spec (steps included), the egress profile, the deadline, the request expectations and probes below, the plan id and the target. The assertion lock and
  the plan digest follow the conventions of `qa-evidence`, so the plan digest covers all of it, and the contracts and the harness must agree on the assertion-set pin;
* needs, per lane, the `requests` the target must have seen (`required`) and may see (`allowed`) as `METHOD /path` strings, and names, for EVERY assertion, a probe: a fact of the independent reference
  check (`settings-persistence`, `discount-rule`) that must not contradict a verified verdict, or `ui-only` (the assertion is about what the browser shows; nothing independent backs it). A lane with an
  assertion that names no probe is refused at freeze, so a plan cannot reach VERIFIED on a fixture-app assertion nobody said anything about; the assertions declared `ui-only` are listed in the report
  (`extensions.no_independent_probe`) and in the summary `run` prints;
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
5. The verdicts are computed by `judge_lane` over the observation file and the frozen assertions, using the harness `DeterministicVerifier`. Before a value
   counts, what the lane claims is checked against what the run itself recorded (`corroborate.py`): the harness run record passes the harness integrity check, is sealed
   and not cancelled, belongs to this run, names the frozen assertion set and the frozen spec, and agrees with every observation; the target's own request
   log for the lane shows the required requests and none the plan does not allow; and an assertion tied to a probe is not verified when the independent reference
   check (run against the target after the lanes) finds that fact deviating, or when there is no reference check. Anything that does not hold leaves the lane's
   assertions `INCONCLUSIVE` (`EVIDENCE_UNUSABLE`). The in-run verifier's verdicts are a cross-check: a disagreement certifies nothing.
   A lane produced by a test double (`RunOptions.lane_command`, used by tests only) carries only `INCONCLUSIVE` with the reason `TEST_DOUBLE` and the report says so
   (`extensions.test_double`).
6. The bundle is built by a pure function (`bundle.build_run_bundle`, no clock, no environment, no file system) with `qa-evidence`, which checks its own output.

Every lane and every frozen assertion is accounted for whatever happens. A lane that cannot start, times out, is cancelled or crashes is recorded with a
native status that says so; its assertions are `INCONCLUSIVE`; the run is never `VERIFIED`. The engine's own status (`lanes[].native`) and the verdict
(`accounting.results[].verdict`) are separate fields with disjoint vocabularies. For the browser lane the native status is the harness executor's outcome
(`PASS` becomes `NATIVE_PASS`, `PRODUCT_FAIL` becomes `NATIVE_FAIL`, anything else `NATIVE_ERROR` or `NATIVE_TIMEOUT`); it is never converted into a verdict.

## Bounded reads

Two mechanisms, for two kinds of files.

* **Paths a user supplies** (a plan or lock; from the next parts also a bundle to verify, report or inspect) are read by a child process (`isolated.py`, `read_worker.py`): the parent holds nothing but what
  came through a pipe, stops taking bytes at the cap (and kills the child), stops waiting at a wall-clock deadline (`REDEVOPS_QA_READ_TIMEOUT`, default 30 s; bundles `REDEVOPS_QA_BUNDLE_READ_TIMEOUT`, default
  120 s) and kills the child, and on SIGINT, SIGTERM or SIGHUP kills the child and ends with exit 3. The child opens the path without blocking (`O_NONBLOCK`), `fstat`s the same descriptor and refuses anything
  that is not a regular file (a FIFO, a device, a directory: never read, `/dev/zero` included), refuses a file above the cap before reading, and reads with a running total (a growing file stops at the cap).
* **Files a lane or the target wrote** (in the run's own temporary directory) are read in this process through `safe_read.read_regular` with the same rules (one descriptor, regular files only, no symbolic
  link, byte cap, deadline checked between chunks) and under one **evidence budget** for the whole run (`REDEVOPS_QA_MAX_EVIDENCE_BYTES` or `RunOptions.max_evidence_bytes`, default 128 MiB, half the cap of
  a bundle): a file that does not fit is neither read nor kept, its name is logged, the lane becomes an engine error `evidence-over-cap`, the report says `extensions.evidence_incomplete`, the run is never
  VERIFIED (exit 3), and everything that fit is in the bundle. If the bundle format still refuses what was collected, the run is rebuilt without the blobs instead of ending as a crash.
* The reference check of the target: no answer above 1 MiB, a total deadline of 30 s for the whole check (a watcher ends the connection; a server that sends a byte every few seconds does not stretch it),
  and the run's cancel ends it.

* The limits from the environment (`REDEVOPS_QA_READ_TIMEOUT`, `REDEVOPS_QA_BUNDLE_READ_TIMEOUT`: 1 to 3600 seconds; `REDEVOPS_QA_MAX_EVIDENCE_BYTES`: 1024 to 8 GiB) are parsed strictly: anything else (`abc`, `nan`,
  `inf`, `0`, a negative or a huge number) is refused with exit 2 and a message that names the variable, before anything starts; never a traceback and never "no limit".
* The core of the in-process read lives in the adapter kit (`qa_adapter_kit.boundedread`) so that the adapters use it too (the Robot adapter's `output.xml` and suite files, the kit's artifact collection). With a
  root (the run's temporary directory) every component below it is opened with `O_NOFOLLOW` relative to its parent's descriptor: a `blobs` directory replaced by a symbolic link is refused, not followed.
* A probe fact is tied to what it speaks for: `settings-persistence` only for the browser assertion on the 'Email notifications' checkbox, `discount-rule` only for a Robot lane's assertion read by the
  evidence program; any other pairing is refused at freeze (`BAD_PROBES`).

**Tested** (each in a child with a hard timeout and, where the platform enforces one, an address-space cap; none opens an unbounded source): a reading child that never answers is killed at the deadline and is
gone; a child that writes without end is stopped at the byte cap; SIGINT, SIGTERM, SIGHUP end the wait and the child; refusals of a FIFO with no writer, a FIFO with a capped writer (nothing is consumed), a
character device, a symlink, a sparse file of 300 MiB, a size that lies at the open and a growing file; the same for `run` and `doctor --plan`; the evidence budget and its fallback; the reference check against a
capped 64 MiB answer, a one-byte-at-a-time body, dripped headers and a cancel during a stall.
**Not tested, only inferred:** a child blocked in UNINTERRUPTIBLE kernel I/O on a hard-hung network or FUSE mount. SIGKILL is sent and the parent does not wait for the child past a short grace, but the
process itself may stay until the kernel returns the I/O (a subprocess timeout does not guarantee that every blocked kernel operation ends). No test has a stalled mount; the "never answers" child is a stand-in.
`RLIMIT_AS` is enforced on Linux and ignored by macOS; on macOS the hard timeouts and the capped writers are the protection.

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
lanes/browser/target-requests.jsonl    the target's own log of the requests it served during this lane (log)
logs/                                  orchestration log, tails of the lane output, the reference check of the target (log)
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
