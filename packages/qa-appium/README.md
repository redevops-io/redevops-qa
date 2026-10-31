# qa-appium

Appium adapters for ReDevOps QA, built on the shared `qa-adapter-kit`. Android first (UiAutomator2). iOS exists only as an interface that reports
`UNAVAILABLE` unless a real, licensed worker is supplied from outside this repository.

```text
InteractiveSession -> MobileInteractiveAdapter -> MobileDriver (protocol) -> AppiumAndroidDriver (Appium Python client 6.1.1, imported lazily)
                                                                          -> FakeDevice (offline tests)
                                                                          -> unavailable_ios_driver (reports UNAVAILABLE)
```

Licence: the family licence of this repository (source-available; see `LICENSE.md`).

## What it does and does not do

* Actions: `open_app` (the session starts for one configured app package and the app must be in the foreground), `tap`, `type` (never echoed),
  `read` (bounded), `check` (a native assertion declaring the assertion id the request names), `back`, `screenshot` (off unless enabled, since an image
  cannot be redacted). Locators are `id=<resource id>` or `acc=<accessibility id>`; there is no XPath.
* It drives an app that is **already installed**. It installs no APK, grants no permission, runs no `adb` or `mobile: shell` command and never reaches a
  host other than the Appium server, which must be on this machine unless the operator names its host.
* **Not redistributed, not downloaded.** The Appium server, the UiAutomator2 driver, the Android SDK and the emulator or device belong to the worker.
  The licence matrix lists the Android SDK and emulator and the Apple toolchain as excluded by default (the Android SDK terms forbid redistribution).
  Nothing in this package installs or fetches any of them.
* **Unavailable is not a pass and not a skip.** A missing client, server, SDK, device or emulator is `ERROR` with `UNAVAILABLE`. Every iOS action is
  `ERROR` `UNAVAILABLE` unless an operator supplies a driver for their own licensed worker.
* Native PASS is never promoted: a `check` is native evidence only through an explicit mapping and a declared id, and the canonical status stays
  `UNVERIFIED`.

## Tests

* **Offline (default).** `python -m pytest packages/qa-appium/tests`: the adapter against a fake device, capabilities, the server policy, the real
  driver's unavailable paths and the iOS interface. The Appium client is not installed and nothing touches the network.
* **Real server, no device.** `tests/real/test_ap_server.py`, marked `appium_server`, run by the `appium-server` CI job: real Appium 3.9.0 server
  (installed with `--ignore-scripts`) and client 6.1.1 on loopback, no Android SDK. It shows that the client talks to the server, that the UiAutomator2
  driver accepts the adapter's capabilities and that a worker without a device is `UNAVAILABLE`. It drives no app.
* **Real emulator or device.** `tests/real/test_ap_android_device.py`, marked `appium_android`, run by the `appium-android` CI job. It needs an
  operator-provisioned Android SDK and an attached emulator or device, which this repository does not provision (no licence is accepted, no system image is
  downloaded). It fails, never skips, when there is none, so on a hosted runner it is expected to be red; it is not a required check and **it has not been
  observed to pass**, so nothing here is a claim about real emulator behaviour.
