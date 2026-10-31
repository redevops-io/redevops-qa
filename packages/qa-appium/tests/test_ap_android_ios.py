# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Android capabilities and server policy, the real driver's unavailable paths, and the iOS interface that reports unavailable."""
import pytest

from ap_support import PKG, act, make_session
from qa_adapter_kit import AdapterFault, ErrorCode, Status
from qa_appium import (CAPABILITIES, DriverFault, FaultKind, MobileConfig, android_capabilities, check_server_url, ios_adapter, unavailable_ios_driver,
                       UNAVAILABLE_MESSAGE, AppiumAndroidDriver)
from qa_adapter_kit import AdapterUnavailable


# ---------------------------------------------------------------------------------------------- android
def test_capabilities_drive_an_installed_app_without_installing_resetting_permissions_or_a_shell():
    caps = android_capabilities(MobileConfig(app_package=PKG))
    assert caps == {"platformName": "Android", "appium:automationName": "UiAutomator2", "appium:appPackage": PKG, "appium:noReset": False,
                    "appium:autoGrantPermissions": False, "appium:newCommandTimeout": 60}
    assert not any(k in caps for k in ("appium:app", "appium:adbExecTimeout", "appium:allowInsecure", "appium:udid"))
    assert android_capabilities(MobileConfig(app_package=PKG), app_activity=".Main")["appium:appActivity"] == ".Main"


@pytest.mark.parametrize("url", ["http://127.0.0.1:4723", "http://localhost:4723/", "https://localhost:4443", "http://[::1]:4723"])
def test_the_server_must_be_on_this_machine_by_default(url):
    assert check_server_url(url) == url


@pytest.mark.parametrize("url", ["http://appium.example.invalid:4723", "http://10.0.0.5:4723", "ftp://127.0.0.1", "http://user:pw@127.0.0.1:4723", "127.0.0.1:4723",
                                 "", "http://[::1", "file:///tmp/s"])
def test_any_other_server_is_refused(url):
    with pytest.raises(AdapterFault):
        check_server_url(url)


def test_a_named_host_is_accepted_only_when_the_operator_lists_it():
    assert check_server_url("http://farm.example.invalid:4723", frozenset({"farm.example.invalid"}))
    with pytest.raises(AdapterFault):
        check_server_url("http://other.example.invalid:4723", frozenset({"farm.example.invalid"}))


def test_the_real_driver_refuses_a_remote_server_before_importing_anything():
    with pytest.raises(AdapterFault):
        AppiumAndroidDriver(MobileConfig(app_package=PKG), server_url="http://appium.example.invalid:4723")


def test_the_real_driver_without_a_reachable_server_or_client_is_unavailable_and_downloads_nothing(tmp_path):
    # no Appium server listens on this port: whether or not the client is installed, session creation cannot succeed
    with pytest.raises(DriverFault) as info:
        AppiumAndroidDriver(MobileConfig(app_package=PKG), server_url="http://127.0.0.1:9")
    assert info.value.kind is FaultKind.UNAVAILABLE


def test_the_real_driver_through_the_adapter_is_an_unavailable_error_never_a_pass(tmp_path):
    from qa_adapter_kit import InteractiveSession
    from qa_appium import android_adapter
    out = tmp_path / "o"
    out.mkdir()
    s = InteractiveSession(android_adapter(lambda: AppiumAndroidDriver(MobileConfig(app_package=PKG), server_url="http://127.0.0.1:9"),
                                           MobileConfig(app_package=PKG)), output_dir=out)
    r = s.perform(act("appium-android-interactive", 0, "open_app"))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.UNAVAILABLE


# ---------------------------------------------------------------------------------------------- ios
@pytest.mark.parametrize("kind,target", [("open_app", ""), ("tap", "acc=Go"), ("type", "id=x"), ("read", "id=x"), ("check", "id=x"), ("back", ""), ("screenshot", "")])
def test_every_ios_action_is_an_unavailable_error_never_a_pass_or_a_skip(tmp_path, kind, target):
    s, adapter, _ = make_session(tmp_path, ios=True)
    kw = {"value": "x"} if kind in ("type", "check") else {}
    r = s.perform(act("appium-ios-interactive", 0, kind, target, **kw))
    assert r.status is Status.ERROR and r.error_code is ErrorCode.UNAVAILABLE and r.native_assertions == () and r.attempts == 1
    assert UNAVAILABLE_MESSAGE in r.error_message


def test_the_ios_interface_is_unavailable_at_every_step_of_a_session(tmp_path):
    s, _, _ = make_session(tmp_path, ios=True)
    statuses = [s.perform(act("appium-ios-interactive", i, "open_app")).status for i in range(3)]
    assert statuses == [Status.ERROR] * 3


def test_the_default_ios_factory_raises_unavailable_and_nothing_else():
    with pytest.raises(AdapterUnavailable, match="licensed worker"):
        unavailable_ios_driver()


def test_an_operator_supplied_ios_driver_is_used_as_is(tmp_path):
    from qa_appium.testing.fake import FakeDevice
    s, _, holder = make_session(tmp_path, ios=True, factory=lambda: FakeDevice(PKG))
    assert s.perform(act("appium-ios-interactive", 0, "open_app")).status is Status.PASS


def test_ios_and_android_manifests_differ_only_in_identity():
    from qa_appium import android_adapter
    a = ios_adapter(MobileConfig(app_package=PKG)).manifest
    b = android_adapter(lambda: None, MobileConfig(app_package=PKG)).manifest
    assert a.adapter_id == "appium-ios-interactive" and b.adapter_id == "appium-android-interactive" and a.capabilities == b.capabilities == CAPABILITIES
    assert a.framework == b.framework and a.network == "none"
