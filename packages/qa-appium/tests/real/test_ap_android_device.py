# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Real Appium against an attached Android emulator or device. Marked ``appium_android``; run only by the ``appium-android`` CI job, which needs a
worker whose operator provisioned the Android SDK and an emulator under Google's terms. This repository does not provision them. It fails, never
skips, when they are absent. It was observed to pass locally on 2026-11-01 (see the package README for the exact environment) and has not run in CI, so
nothing here is a claim about other API levels, physical devices or iOS."""
import pytest

from qa_adapter_kit import InteractiveActionRequest, InteractiveSession, Status
from qa_appium import AppiumAndroidDriver, MobileConfig, android_adapter

pytestmark = pytest.mark.appium_android
SETTINGS = MobileConfig(app_package="com.android.settings", allow_screenshots=True)


def act(step, kind, target="", **kw):
    return InteractiveActionRequest(session_id="d1", adapter_id="appium-android-interactive", step_index=step, kind=kind, target=target, **kw)


def test_the_settings_app_opens_on_the_attached_device_and_a_screenshot_is_a_real_png(appium_client, server_url, tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    s = InteractiveSession(android_adapter(lambda: AppiumAndroidDriver(SETTINGS, server_url=server_url, app_activity=".Settings"), SETTINGS), output_dir=out)
    try:
        assert s.perform(act(0, "open_app")).status is Status.PASS
        shot = s.perform(act(1, "screenshot"))
        assert shot.status is Status.PASS and (out / shot.artifacts[0].path).read_bytes().startswith(b"\x89PNG")
    finally:
        s.close()
