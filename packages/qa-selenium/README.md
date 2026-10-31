# qa-selenium

Selenium (Python) adapters for ReDevOps QA, built on the shared `qa-adapter-kit`. Selenium is an optional, pinned extra
(`selenium==4.52.0`, Apache-2.0; see `third_party/adapter-license-matrix.yaml`). It is not bundled, and nothing is downloaded.

```text
interactive:  InteractiveSession -> SeleniumInteractiveAdapter -> BrowserDriver (protocol) -> SeleniumChromeDriver (real; Selenium imported lazily)
                                                                                           -> FakeBrowser (offline tests)
suite:        SuiteRunner -> SeleniumSuiteAdapter -> supervised `python -m pytest <suite> --junitxml=...` -> JUnit XML -> native assertions
```

Licence: the family licence of this repository (source-available; see `LICENSE.md`).

## Interactive adapter

Actions `open`, `click`, `type`, `read`, `check`, `screenshot`, one at a time under the session's step, retry and deadline budgets.

* Navigation is default deny: only `http` and `https` URLs without credentials whose host (or `host:port`) is on the allowlist; a
  redirect to another host is refused and the browser is sent to a blank page. This is a check on navigation, not a network filter:
  sub-resource requests of an allowed page are not filtered here (use the egress gateway for that).
* Locators are `css=`, `id=`, `name=` or `testid=` with a bounded value; there is no XPath.
* `type` takes a value or a secret value and never echoes it; `read` is bounded and redacted by the session; errors never contain page
  content, only a fixed code such as `NOT_FOUND` or `STALE`.
* `check` compares an element's text with an expected value and returns a **native** assertion that declares the assertion id the
  request names. It is evidence for a canonical assertion only through an explicit mapping, and is never an oracle verdict.
* Screenshots are off unless enabled, because an image cannot be redacted.
* Stale and not-interactable elements are retried within the session's retry limit; a missing element, a timeout and a browser crash are
  not. A missing Selenium, browser or driver executable is `ERROR` with code `UNAVAILABLE`: never a pass, never a skip, no fallback.

## Suite adapter

Runs an existing pytest-based Selenium suite as one supervised process and imports the JUnit XML it wrote. It does not steer a test.
The report is read strictly: a DOCTYPE or entity declaration, an oversized report, a testcase without a name and declared counts that
disagree with the testcases are refused; exit codes other than 0, 1 and 5 mean the report is not trusted. A testcase is one native
assertion (ERROR over FAIL over SKIP over PASS). A property `qa-assert` (pytest's `record_property`) declares the canonical assertion id
a test is evidence for. Selectors are plain test names passed to `-k`.

The suite gets the paths of the worker's browser and driver through `QA_CHROME_BINARY`, `QA_CHROMEDRIVER_PATH` and `QA_BASE_URL`
and must hand the driver path to Selenium (`Service(executable_path=...)`); Selenium 4.52.0 then skips Selenium Manager, which would
otherwise download drivers and browsers. The real-browser lane checks that.

## Tests

* **Offline (default).** `python -m pytest packages/qa-selenium/tests` (also part of the repository run): the interactive adapter
  against the fake browser, the JUnit importer against reports recorded from real pytest runs and against hostile ones, and the suite
  adapter running real pytest under the supervisor over a small suite (every status, timeout, environment scrubbing, sealed-run
  refusals, native PASS never promoted). Selenium is not installed and nothing touches the network.
* **Real browser.** `tests/browser`, every test marked `browser`, run only by the `selenium-browser` CI job (Selenium 4.52.0 pinned, the
  runner's Chrome and ChromeDriver, read-only, no secret). It fails, never skips, when Selenium, Chrome or the driver is missing, and it
  is not a required check until it has been shown to pass. It covers the real driver against a page served from loopback and a real
  Selenium suite run under the supervisor.
