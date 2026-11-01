# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The driver layer: importing is lazy, the real driver fails typed when Playwright is missing, the classifier of
Playwright errors is a closed table, and the fake driver satisfies the same protocol the real one does."""
import subprocess
import sys
import types
from pathlib import Path

import pytest
from agent_harness.qa.errors import EnvironmentUnhealthy
from qa_playwright import (BrowserDriver, DriverFault, DriverSession, DriverUnavailable, FaultKind, PlaywrightDriver)
from qa_playwright.playwright_driver import _ARIA_LINE, _css_string, classify_error
from qa_playwright.testing.fake import FakeBrowserDriver

from qa_pw_support import make_world, login_page

SRC = Path(__file__).resolve().parents[1] / "src"


def test_importing_the_package_never_imports_playwright(pins):
    code = ("import sys, qa_playwright, qa_playwright.testing.fake; "
            "bad = [m for m in sys.modules if m.split('.')[0] == 'playwright']; sys.exit(1 if bad else 0)")
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": f"{SRC}:{pins.harness_qa.resolved_path}",
           "PYTHONDONTWRITEBYTECODE": "1"}
    done = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def test_the_real_driver_is_a_typed_error_when_playwright_is_missing_and_there_is_no_fallback(monkeypatch):
    monkeypatch.setitem(sys.modules, "playwright", None)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    with pytest.raises(DriverUnavailable) as err:
        PlaywrightDriver()
    assert isinstance(err.value, EnvironmentUnhealthy) and err.value.code == "ENVIRONMENT_UNHEALTHY"
    assert not err.value.recoverable and err.value.details["reason"] in ("ImportError", "ModuleNotFoundError")


def test_the_real_driver_is_a_typed_error_when_the_start_of_playwright_fails():
    class Mod:
        @staticmethod
        def sync_playwright():
            class M:
                def start(self):
                    raise RuntimeError("driver missing: /secret/path")
            return M()
    with pytest.raises(DriverUnavailable) as err:
        PlaywrightDriver(module=Mod)
    assert "/secret/path" not in str(err.value) and err.value.details == {"reason": "RuntimeError"}


def test_the_real_driver_wraps_a_browser_that_cannot_be_launched_as_driver_unavailable():
    class Chromium:
        def launch(self, **kwargs):
            raise OSError("executable missing at /nowhere")

    class Pw:
        chromium = Chromium()

    class Mod:
        @staticmethod
        def sync_playwright():
            class M:
                def start(self):
                    return Pw()

                def stop(self):
                    pass
            return M()
    from qa_playwright import ContextSpec
    driver = PlaywrightDriver(module=Mod)
    with pytest.raises(DriverUnavailable) as err:
        driver.new_session(ContextSpec(session_id="s", profile_id="p"))
    assert "/nowhere" not in str(err.value)
    driver.close()


def test_the_launch_passes_the_args_and_the_proxy_and_never_a_download_or_a_profile_dir():
    seen = {}

    class Chromium:
        def launch(self, **kwargs):
            seen.update(kwargs)
            raise OSError("stop here")

    class Pw:
        chromium = Chromium()

    class Mod:
        @staticmethod
        def sync_playwright():
            class M:
                def start(self):
                    return Pw()

                def stop(self):
                    pass
            return M()
    from qa_playwright import ContextSpec, ProxySettings
    driver = PlaywrightDriver(module=Mod)
    with pytest.raises(DriverUnavailable):
        driver.new_session(ContextSpec(session_id="s", profile_id="p", launch_args=("--a",),
                                       proxy=ProxySettings(server="http://127.0.0.1:1", bypass="<-loopback>")))
    assert seen["args"] == ["--a"] and seen["proxy"] == {"server": "http://127.0.0.1:1", "bypass": "<-loopback>"}
    assert not {"user_data_dir", "storage_state", "downloads_path"} & set(seen)


@pytest.mark.parametrize("name,text,kind", [
    ("TimeoutError", "Timeout 5000ms exceeded", FaultKind.TIMEOUT),
    ("Error", "Target page, context or browser has been closed", FaultKind.SESSION_CLOSED),
    ("Error", "Page crashed", FaultKind.CRASHED),
    ("Error", "net::ERR_BLOCKED_BY_CLIENT at http://x/", FaultKind.NAVIGATION_BLOCKED),
    ("Error", "net::ERR_TUNNEL_CONNECTION_FAILED at https://x/", FaultKind.NAVIGATION_BLOCKED),
    ("Error", "Element is not attached to the DOM", FaultKind.DETACHED),
    ("Error", "ElementHandle.evaluate: Protocol error (DOM.describeNode): Cannot find context with specified id", FaultKind.DETACHED),
    ("Error", "Execution context was destroyed, most likely because of a navigation", FaultKind.DETACHED),
    ("Error", "<div> intercepts pointer events", FaultKind.OBSCURED),
    ("Error", "Element is not visible", FaultKind.NOT_VISIBLE),
    ("Error", "Element is not enabled", FaultKind.DISABLED),
    ("Error", "Element is not editable", FaultKind.NOT_EDITABLE),
    ("Error", "something else entirely", FaultKind.OTHER)])
def test_playwright_errors_are_classified_and_the_text_is_dropped(name, text, kind):
    exc = type(name, (Exception,), {})(text)
    fault = classify_error(exc)
    assert fault.kind is kind and text not in str(fault)


def test_the_aria_line_parser_reads_role_and_name_and_ignores_attributes():
    assert _ARIA_LINE.match('- button "Save changes" [disabled]').groups() == ("button", "Save changes")
    assert _ARIA_LINE.match("- heading").groups() == ("heading", None)
    assert _ARIA_LINE.match('- textbox "Say \\"hi\\"":').group(2) == 'Say \\"hi\\"'
    assert _ARIA_LINE.match("not an aria line") is None


def test_css_string_quotes_and_refuses_control_characters():
    assert _css_string('a"b\\c') == '"a\\"b\\\\c"'
    with pytest.raises(DriverFault) as err:
        _css_string("a\nb")
    assert err.value.kind is FaultKind.INVALID


def test_the_fake_driver_and_its_session_satisfy_the_driver_protocols():
    w = make_world(login_page())
    assert isinstance(w.driver, BrowserDriver)
    h = w.open()
    assert isinstance(w.driver.sessions[h.session_id], DriverSession)
    assert isinstance(FakeBrowserDriver(), BrowserDriver)


def test_a_driver_fault_message_is_its_kind_and_nothing_else():
    fault = DriverFault(FaultKind.OBSCURED, obscurer_role="dialog")
    assert str(fault) == "OBSCURED" and fault.obscurer_role == "dialog"
