# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The real-browser lane: Selenium 4.52.0 with Chrome against a page served from loopback by the test. Every test is marked ``browser``
and runs only in the ``selenium-browser`` CI job. It proves that the real driver does what the fake driver models; it does not prove
anything about other browsers or about pages on the internet."""
import logging
import os
import sys
import textwrap

import pytest

from qa_adapter_kit import ErrorCode, InteractiveActionRequest, InteractiveSession, Limits, Status, SuiteRunRequest, SuiteRunner
from qa_selenium import (AdapterConfig, DriverFault, FaultKind, SELENIUM_EXCEPTION_KINDS, SeleniumChromeDriver, SeleniumInteractiveAdapter,
                         SeleniumSuiteAdapter, classify_exception, interactive_manifest, suite_manifest)

pytestmark = pytest.mark.browser


def act(step, kind, target="", **kw):
    return InteractiveActionRequest(session_id="b1", adapter_id="selenium-interactive", step_index=step, kind=kind, target=target, **kw)


def session(tmp_path, chrome_paths, site, **cfg):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    driver, binary = chrome_paths
    adapter = SeleniumInteractiveAdapter(lambda: SeleniumChromeDriver(driver, binary), config=AdapterConfig(allowed_hosts=frozenset({site}), wait_s=3, **cfg),
                                         manifest=interactive_manifest(limits=Limits(deadline_s=90, max_steps=20, max_retries=1)))
    return InteractiveSession(adapter, output_dir=out), adapter


# ---------------------------------------------------------------------------------------------- needs Selenium only
def test_every_mapped_exception_name_is_a_class_of_the_pinned_selenium(selenium_installed):
    import selenium.common.exceptions as ex
    for name in SELENIUM_EXCEPTION_KINDS:
        assert hasattr(ex, name), f"{name} is not a class of Selenium {selenium_installed}"


def test_real_selenium_exceptions_classify_as_the_map_says(selenium_installed):
    import selenium.common.exceptions as ex
    assert classify_exception(ex.NoSuchElementException()) is FaultKind.NOT_FOUND
    assert classify_exception(ex.StaleElementReferenceException()) is FaultKind.STALE
    assert classify_exception(ex.ElementClickInterceptedException()) is FaultKind.NOT_INTERACTABLE
    assert classify_exception(ex.TimeoutException()) is FaultKind.TIMEOUT
    assert classify_exception(ex.NoSuchDriverException()) is FaultKind.UNAVAILABLE
    assert classify_exception(ex.WebDriverException()) is FaultKind.CRASH


def test_missing_executables_make_the_real_driver_unavailable_and_nothing_is_downloaded(selenium_installed, tmp_path):
    with pytest.raises(DriverFault) as info:
        SeleniumChromeDriver(str(tmp_path / "no-chromedriver"), str(tmp_path / "no-chrome"))
    assert info.value.kind is FaultKind.UNAVAILABLE


# ---------------------------------------------------------------------------------------------- needs Chrome and its driver
def test_open_type_click_read_and_check_against_a_real_page(tmp_path, chrome_paths, site):
    s, _ = session(tmp_path, chrome_paths, site)
    try:
        assert s.perform(act(0, "open", f"http://{site}/")).status is Status.PASS
        assert s.perform(act(1, "read", "id=title")).observations[0].summary == "text of id=title: Hello world"
        assert s.perform(act(2, "type", "name=user", value="Ada")).status is Status.PASS
        assert s.perform(act(3, "click", "testid=go")).status is Status.PASS
        assert s.perform(act(4, "read", "id=out")).observations[0].summary == "text of id=out: Clicked Ada"
        ok = s.perform(act(5, "check", "id=out", value="Clicked Ada", assertion_id="A-1"))
        bad = s.perform(act(6, "check", "id=out", value="Clicked Bob", assertion_id="A-1"))
        assert ok.status is Status.PASS and bad.status is Status.FAIL
    finally:
        s.close()


def test_a_missing_element_is_reported_as_not_found_after_a_bounded_wait(tmp_path, chrome_paths, site):
    s, _ = session(tmp_path, chrome_paths, site)
    try:
        assert s.perform(act(0, "open", f"http://{site}/")).status is Status.PASS
        r = s.perform(act(1, "click", "id=does-not-exist"))
        assert r.status is Status.ERROR and "NOT_FOUND" in r.error_message and r.attempts == 1
        c = s.perform(act(2, "check", "id=does-not-exist", value="x", assertion_id="A-1"))
        assert c.status is Status.FAIL
    finally:
        s.close()


def test_a_navigation_to_a_host_that_is_not_allowed_never_reaches_the_browser(tmp_path, chrome_paths, site):
    s, adapter = session(tmp_path, chrome_paths, site)
    try:
        r = s.perform(act(0, "open", "http://example.invalid/"))
        assert r.status is Status.ERROR and r.error_code is ErrorCode.INVALID_REQUEST and adapter._driver is None
    finally:
        s.close()


def test_a_redirect_off_the_allowlist_is_refused_and_the_browser_is_sent_to_a_blank_page(tmp_path, chrome_paths, site):
    s, adapter = session(tmp_path, chrome_paths, site)
    try:
        r = s.perform(act(0, "open", f"http://{site}/redirect"))
        assert r.status is Status.ERROR
    finally:
        s.close()


def test_selenium_manager_is_skipped_because_the_driver_path_is_given(tmp_path, chrome_paths, caplog):
    caplog.set_level(logging.DEBUG, logger="selenium")
    driver = SeleniumChromeDriver(*chrome_paths)
    try:
        assert any("Skipping Selenium Manager" in rec.getMessage() for rec in caplog.records)
    finally:
        driver.quit()


def test_each_driver_starts_with_a_fresh_profile_and_cleans_it_up(chrome_paths, site):
    first = SeleniumChromeDriver(*chrome_paths)
    profile = first._profile
    try:
        first.open(f"http://{site}/set-cookie", 5)
    finally:
        first.quit()
    assert not os.path.exists(profile)
    second = SeleniumChromeDriver(*chrome_paths)
    try:
        second.open(f"http://{site}/", 5)
        from qa_selenium import parse_locator
        assert second.read_text(parse_locator("id=cookie"), 5) == "cookie:"
    finally:
        second.quit()


def test_a_screenshot_is_a_real_png_when_enabled(tmp_path, chrome_paths, site):
    s, _ = session(tmp_path, chrome_paths, site, allow_screenshots=True)
    try:
        assert s.perform(act(0, "open", f"http://{site}/")).status is Status.PASS
        r = s.perform(act(1, "screenshot"))
        assert r.status is Status.PASS and (tmp_path / "out" / r.artifacts[0].path).read_bytes().startswith(b"\x89PNG")
    finally:
        s.close()


def test_a_real_selenium_suite_runs_under_the_supervisor_and_its_junit_is_imported(tmp_path, chrome_paths, site):
    ws, out = tmp_path / "workspace", tmp_path / "output"
    (ws / "suite").mkdir(parents=True)
    out.mkdir()
    (ws / "suite" / "test_real.py").write_text(textwrap.dedent('''
        import os
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.common.by import By


        def make():
            o = Options()
            o.binary_location = os.environ["QA_CHROME_BINARY"]
            for a in ("--headless=new", "--no-first-run", "--disable-dev-shm-usage", "--disable-component-update"):
                o.add_argument(a)
            return webdriver.Chrome(service=Service(executable_path=os.environ["QA_CHROMEDRIVER_PATH"]), options=o)


        def test_title(record_property):
            record_property("qa-assert", "A-1")
            d = make()
            try:
                d.get(os.environ["QA_BASE_URL"])
                assert d.find_element(By.ID, "title").text == "Hello world"
            finally:
                d.quit()


        def test_wrong_text(record_property):
            record_property("qa-assert", "A-2")
            d = make()
            try:
                d.get(os.environ["QA_BASE_URL"])
                assert d.find_element(By.ID, "title").text == "Something else"
            finally:
                d.quit()
        '''))
    driver, binary = chrome_paths
    adapter = SeleniumSuiteAdapter(sys.executable, suite_manifest(sys.executable, limits=Limits(deadline_s=240, output_limit_bytes=500_000, kill_grace_s=5)))
    req = SuiteRunRequest(run_id="real-1", adapter_id="selenium-suite", workspace=str(ws), suite_path="suite/test_real.py", output_dir=str(out),
                          env={"QA_CHROMEDRIVER_PATH": driver, "QA_CHROME_BINARY": binary, "QA_BASE_URL": f"http://{site}/"})
    r = SuiteRunner(adapter).run(req)
    got = {a.name: a.status for a in r.native_assertions}
    assert got == {"test_title": Status.PASS, "test_wrong_text": Status.FAIL}, (r.status, r.error_code, r.stdout_tail[-500:], r.stderr_tail[-500:])
    assert r.status is Status.FAIL
