# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``qa_playwright``: the browser adapter of ReDevOps QA.

``PlaywrightAdapter`` implements the ``qa-adapter/1`` protocol over a small :class:`BrowserDriver` protocol. The real driver
(``PlaywrightDriver``) imports ``playwright.sync_api`` only when it is constructed, and fails with ``DriverUnavailable`` if
Playwright is missing; importing this package never imports Playwright.
"""
from .adapter import ADAPTER_ID, ADAPTER_VERSION, API_VERSION, PlaywrightAdapter
from .config import DEFAULT_CAPTURE, AdapterConfig, EgressProfile
from .driver import (BrowserDriver, CloseReport, ConsoleEvent, ContextSpec, DriverFault, DriverSession, ElementInfo,
                     ElementQuery, ElementReading, EventLog, FaultKind, NetworkEvent, PageMeta, ProxySettings,
                     RequestGate, RequestInfo)
from .errors import DriverUnavailable
from .payload import ActionReceiptPayload

__version__ = ADAPTER_VERSION


def PlaywrightDriver(*args, **kwargs):          # noqa: N802 (a class-like factory so that importing stays lazy)
    """Construct the real driver. Imports ``playwright.sync_api`` here, not at package import."""
    from .playwright_driver import PlaywrightDriver as _Driver
    return _Driver(*args, **kwargs)


__all__ = [
    "ADAPTER_ID", "ADAPTER_VERSION", "API_VERSION", "PlaywrightAdapter", "PlaywrightDriver", "AdapterConfig", "EgressProfile",
    "DEFAULT_CAPTURE", "BrowserDriver", "DriverSession", "ContextSpec", "ProxySettings", "RequestInfo", "RequestGate",
    "ElementQuery", "ElementInfo", "ElementReading", "PageMeta", "ConsoleEvent", "NetworkEvent", "EventLog", "CloseReport",
    "DriverFault", "FaultKind", "DriverUnavailable", "ActionReceiptPayload", "__version__",
]
