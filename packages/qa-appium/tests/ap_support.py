# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
from qa_adapter_kit import InteractiveActionRequest, InteractiveSession, Limits
from qa_appium import MobileConfig, android_adapter, ios_adapter
from qa_appium.testing.fake import FakeDevice

PKG = "com.example.app"


def make_session(tmp_path, *, device=None, config=None, factory=None, limits=None, ios=False):
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    holder = {}

    def default():
        holder["device"] = device or FakeDevice(PKG)
        return holder["device"]

    cfg = config or MobileConfig(app_package=PKG)
    adapter = (ios_adapter(cfg, factory, limits=limits) if ios else android_adapter(factory or default, cfg, limits=limits))
    return InteractiveSession(adapter, output_dir=out), adapter, holder


def act(adapter_id, step, kind, target="", **kw):
    return InteractiveActionRequest(session_id="m1", adapter_id=adapter_id, step_index=step, kind=kind, target=target, **kw)


def a(step, kind, target="", **kw):
    return act("appium-android-interactive", step, kind, target, **kw)
