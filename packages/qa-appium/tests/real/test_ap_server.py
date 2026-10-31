# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Real Appium 3.9.0 server and client 6.1.1, no device. Marked ``appium_server``; run only by the ``appium-server`` CI job. It shows that the
client talks to a real server, that the UiAutomator2 driver is installed and accepts the capabilities the adapter sends, and that a worker without
an Android SDK or device is reported as ``UNAVAILABLE``. It does not drive any app."""
import pytest

from qa_adapter_kit import ErrorCode, InteractiveActionRequest, InteractiveSession, Status
from qa_appium import AppiumAndroidDriver, DriverFault, FaultKind, MobileConfig, android_adapter, android_capabilities

pytestmark = pytest.mark.appium_server
CONFIG = MobileConfig(app_package="com.example.app")


def test_the_server_is_the_pinned_release_and_the_client_is_the_pinned_release(appium_client, server_url):
    assert appium_client == "6.1.1" and server_url.startswith("http://127.0.0.1:")


def test_the_uiautomator2_driver_is_installed_and_accepts_the_capabilities_the_adapter_sends(appium_client, server_url):
    from appium import webdriver
    from appium.options.android import UiAutomator2Options
    options = UiAutomator2Options().load_capabilities(android_capabilities(CONFIG))
    with pytest.raises(Exception) as info:
        webdriver.Remote(server_url, options=options)
    text = str(info.value)
    # the session cannot start without a device, but it must fail for that reason: not because the driver is missing or a capability was refused
    assert "Could not find a driver" not in text and "Invalid capabilit" not in text and "InvalidArgument" not in text and "automationName" not in text.split("Stacktrace")[0], text[:400]


def test_the_real_driver_reports_a_worker_without_a_device_as_unavailable(appium_client, server_url):
    with pytest.raises(DriverFault) as info:
        AppiumAndroidDriver(CONFIG, server_url=server_url)
    assert info.value.kind is FaultKind.UNAVAILABLE


def test_through_the_adapter_a_worker_without_a_device_is_an_unavailable_error_never_a_pass_or_a_skip(appium_client, server_url, tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    s = InteractiveSession(android_adapter(lambda: AppiumAndroidDriver(CONFIG, server_url=server_url), CONFIG), output_dir=out)
    r = s.perform(InteractiveActionRequest(session_id="m1", adapter_id="appium-android-interactive", step_index=0, kind="open_app"))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.UNAVAILABLE and r.native_assertions == ()


def test_a_remote_server_is_refused_before_any_connection(appium_client):
    from qa_adapter_kit import AdapterFault
    with pytest.raises(AdapterFault):
        AppiumAndroidDriver(CONFIG, server_url="http://appium.example.invalid:4723")
