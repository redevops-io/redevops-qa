# qa-playwright

The browser adapter of ReDevOps QA. `PlaywrightAdapter` implements the `qa-adapter/1` protocol (`open_session`, `observe`,
`locate`, `act`, `assert_`, `capture`, `reset`, `close_session`) in the neutral form defined by the harness QA module; the
bridge converts to and from the contracts form. It is a thin **driver layer** (`BrowserDriver`) under **adapter logic**
that is tested offline.

```text
runner  ->  PlaywrightAdapter  ->  BrowserDriver (protocol)  ->  PlaywrightDriver   (real Chromium; playwright imported lazily)
                                                              ->  FakeBrowserDriver  (offline tests; qa_playwright.testing.fake)
```

Licence: the family licence of this repository (source-available; see `LICENSE.md`). Playwright (Apache-2.0) is an optional,
pinned extra and is imported only by the real driver.

## Guarantees

| Guarantee | How it is kept |
|---|---|
| One fresh, ephemeral context per session; nothing shared | `ContextSpec` has no field for stored state or a profile directory; `open_session` asks for a new context, `reset(CONTEXT)` replaces it, `close_session` reports what was released and what leaked |
| Page content is data, never an instruction | The adapter holds no reference to a policy, a spec, an assertion set or a verifier (checked by an import test). Error texts are fixed and `details` hold only closed-vocabulary values; a driver failure is classified and its text dropped |
| Redaction before anything leaves | Every URL, name, text value, DOM metadata item, snapshot, excerpt and image goes through the injected `Redactor`; only redacted bytes reach the `BlobSink`. A refusing, failing or malformed hook is `RedactionFailed` and the artifact is dropped. An input over the raw bound is refused whole, never cut before redaction |
| Locators never guess | `locate` returns every candidate with role, accessible name, visibility, enabled state and a uniqueness flag. `act` re-checks its candidate immediately before acting and refuses one that is gone (`LocatorNotFound`) or no longer unique (`LocatorAmbiguous`) |
| Every action carries a policy decision reference | `ActionBlockedByPolicy` before the driver is touched otherwise; an optional hook can reject a reference the runner does not recognise |
| `assert_` reads, it does not judge | It takes a subject only. No expected value exists anywhere in the module, and `ObservedValue` has no verdict |
| Deterministic time | Every wait is a bounded poll against the injected `Clock`; the driver only sleeps. A clock that never advances cannot make a loop run forever |
| Network defence in depth | Every request the browser makes, and every redirect hop before it is requested (a DevTools response-stage interception, since a route only sees the first URL), passes a request gate built from the operator's allow-list (default deny), and a navigation is checked before it is attempted. The egress gateway (`qa-egress`) is the enforcement point; this is a second layer |

## What each operation does

* `open_session(profile)`: refuses a redaction policy other than the redactor's and an egress profile that is not configured.
  Downloads, popups and file choosers are off unless the session profile allows them; service workers are blocked; no
  permission is granted; locale, timezone and viewport are fixed.
* `locate(target, mode)`: `EXACT` is equality on role, name, label and test id; `SEMANTIC` is a case-insensitive substring and
  also uses `text_hint`. A descriptor with nothing to match on is refused. Zero matches is an empty result (after a bounded
  wait for the element to appear), not an error. At most `max_candidates` candidates are returned and none is then unique.
* `act(action, target)`: kinds `click`, `fill`, `press`, `select`, `check`, `uncheck`, `hover`, `navigate` and `resolve`
  (resolve checks the target and changes nothing). The target must be a candidate this session's `locate` produced, for the
  locator it names. The adapter waits (on the injected clock) for the target to be visible, enabled, editable where the action
  needs it, and not covered; at the deadline the error says why. A secret reference is resolved by an injected resolver and
  the value is never kept. Every successful action leaves an `ActionReceiptPayload` (`receipt_payloads(handle)`): exact
  locator and strategy, action kind, the value digest (never the value), and the state hash before and after, computed with the
  harness `state_hash` over an observation built the way `observe` builds one.
* `observe(request)`: URL, frame, bounded DOM metadata, an accessibility snapshot, a screenshot digest, and on request console
  and network excerpts. With no kinds requested the default set is snapshot, DOM metadata and screenshot. A redactor that has
  not been configured to accept `image/png` refuses the screenshot (fail closed): list the media type in the redaction
  configuration, or take the screenshot out of `AdapterConfig.default_capture`.
* `assert_(subject)`: `UI_ELEMENT` resolves among *visible* elements through the frozen locator and then only through the
  alternates listed in the subject; several matches are `AMBIGUOUS`, none `UNRESOLVED`, and the value is the whitespace-normalised
  text (form controls: their value; checkboxes: a boolean). `URL` reads the current URL. `RESPONSE` reads the status of the one
  response whose URL (without query) matches the pattern. A value the redactor changed, an over-long value and a password field
  are returned as a digest only, so they can neither pass nor fail an equality by accident and an `ABSENT` check still fails on them.
* `capture(kinds)`: the same artifacts as references. `TRACE` is off by default (`AdapterConfig.allow_trace`); when on it is a
  restricted artifact that must pass the redaction hook like everything else.

## Typed errors

| Driver or adapter condition | Error (`code`) |
|---|---|
| context closed from outside | `SessionLost` (`SESSION_LOST`) |
| renderer or browser crash | `BrowserCrash` (`BROWSER_CRASH`); the session is unusable afterwards |
| driver wait ran out | `ActionTimeout` (`ACTION_TIMEOUT`) |
| element detached (re-render), its document replaced (a navigation by an action or a click, a reload) or never produced by `locate` | `LocatorNotFound` (`LOCATOR_NOT_FOUND`); a new `locate` resolves against the current document |
| target no longer unique | `LocatorAmbiguous` (`LOCATOR_AMBIGUOUS`) |
| hidden, disabled, not editable, covered | `TargetNotActionable` (`TARGET_NOT_ACTIONABLE`) |
| covered by a dialog / a dialog interrupted | `UnexpectedDialog` (`UNEXPECTED_DIALOG`) |
| request gate or allow-list refused | `NavigationDenied` (`NAVIGATION_DENIED`) |
| no decision reference | `ActionBlockedByPolicy` (`ACTION_BLOCKED_BY_POLICY`) |
| redaction hook refused, failed or returned something unusable | `RedactionFailed` (`REDACTION_FAILED`) |
| size bound | `ResourceLimitExceeded` (`RESOURCE_LIMIT_EXCEEDED`) |
| context could not be reset | `ResetFailed` (`RESET_FAILED`) |
| unsupported kind, subject or scope | `UnsupportedOperation` (`UNSUPPORTED_OPERATION`) |
| Playwright or the browser missing, secret not resolvable | `DriverUnavailable` / `EnvironmentUnhealthy` (`ENVIRONMENT_UNHEALTHY`) |
| anything else from the driver | `AdapterCrash` (`ADAPTER_CRASH`), naming only the exception class |

`DriverUnavailable` keeps the code of its parent: the bridge maps errors by code, so a code of its own would be unmapped.

## Use

```python
from qa_playwright import AdapterConfig, EgressProfile, PlaywrightAdapter, PlaywrightDriver

adapter = PlaywrightAdapter(PlaywrightDriver(), blobs=blob_sink, redactor=redactor, clock=SystemClock(),
                            egress_profiles={"main": EgressProfile("main", policy, resolver, launch_args, proxy)})
```

`blob_sink`, `redactor` and `clock` are the harness ports; `policy` is an `EgressPolicy` from the operator's configuration.
`launch_args` and `proxy` come from `qa_egress.launch` so that the browser can reach nothing but the egress gateway.
`PlaywrightDriver()` raises `DriverUnavailable` when Playwright is not installed; there is no fallback and the browser is
never downloaded at run time.

## Threads

Playwright's sync API refuses to start on a thread that already runs an asyncio loop, and its objects belong to the thread that
started it. `PlaywrightDriver` therefore owns one worker thread (no loop; started on first use; a daemon; joined by `close`) and
runs every Playwright call on it, including start-up, launch, every page call, tracing, screenshots and teardown. The adapter holds a
`ThreadedSession` that hands each call to the worker, so the driver can be constructed and used from any thread or loop. A call that
does not return within its bound (the call's own timeout plus a slack, or `call_timeout_s`) is a `TIMEOUT` and makes the worker
unusable (`CRASHED` afterwards); a worker that ends is `CRASHED`; a call after `close` is `SESSION_CLOSED` and a new session is
`DriverUnavailable`. If `close` cannot end a stuck worker it returns after `join_timeout_s` and `leaked_worker` is true. The
bounds are wall-clock bounds on the hand-off; the adapter's own deadlines stay on the injected clock. Exception text from
Playwright is classified and dropped on the worker, as before.

## Install and pins

`pip install "redevops-qa-playwright[browser]"` pulls `playwright==1.64.1`; the browser itself comes from a separate, credential-free
`python -m playwright install --with-deps chromium` step (the CI job does exactly that). Chromium on Ubuntu 24.04 is the
gating target. The package has no other runtime dependency; the harness neutral module and the bridge are the repository's pinned
trees (`pins.toml`).

## Tests

* **Offline (default).** `python -m pytest` from the repository root: the adapter logic against the deterministic fake driver
  (pages, roles, names, visibility, ambiguity, delays, overlays, a stale element, a lost session, slow actions, a request gate,
  per-context storage), the error map, redaction, determinism across hash seeds, import boundaries and mutation tests (each guard
  is removed in turn and the suite notices). No skip, no browser, no network.
* **Real browser.** `tests/browser`, every test marked `browser`, collected only when named explicitly and run only by the
  `browser` job of `.github/workflows/tests.yml` (pinned Playwright, installed Chromium, read-only permissions, no secret). The
  lane fails, it never skips, when Playwright is missing. It proves the driver does what the fake driver models, against a small
  static site the test serves from loopback.
