# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A fake ``playwright.sync_api`` with documents, for the one rule of the real API the element-reference tests depend on: an
element handle belongs to the document (execution context) it was created in. Once that document is replaced, every use of the
handle fails with the browser's own protocol error (``Cannot find context with specified id``), and an element of a replaced
document is never the same object as the element of the new one, even when both look identical.

It builds on :mod:`qa_pw_fakepw` (thread ownership, recorded calls) and adds pages made of elements, locators and handles."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import qa_pw_fakepw as base

CONTEXT_GONE = "ElementHandle.evaluate: Protocol error (DOM.describeNode): Cannot find context with specified id"


@dataclass
class El:
    """One element of a document. ``goes_to`` makes a click navigate (like a link); ``value`` is what a fill typed."""

    role: str
    name: str
    goes_to: Optional[str] = None
    value: str = ""
    clicks: int = 0


class Doc:
    """One document: its elements, its frame, and whether it is still the document the frame shows."""

    def __init__(self, frame: "Frame", elements: List[El]) -> None:
        self.frame = frame
        self.elements = elements
        self.alive = True


class Frame:
    pass


class Handle(base._Obj):
    def __init__(self, world: base.World, doc: Doc, el: El) -> None:
        super().__init__(world)
        self.doc, self.el, self.disposed = doc, el, False

    def _use(self) -> None:
        self._world.touch("handle")
        if self._world.session_closed:
            raise base.Error("Target page, context or browser has been closed")
        if not self.doc.alive:
            raise base.Error(CONTEXT_GONE)

    def evaluate(self, script: str, *args: Any) -> Any:
        self._use()
        if "findIndex" in script:
            others = args[0]
            for other in others:
                other._use()                                 # a handle of a replaced document cannot be passed to the page
            return next((i for i, other in enumerate(others) if other.el is self.el), -1)
        if "isConnected" in script:
            return self.el in self.doc.elements
        return None                                          # the "is it covered" probe: nothing covers anything

    def owner_frame(self) -> Frame:
        self._world.touch("owner_frame")
        return self.doc.frame

    def dispose(self) -> None:
        self._world.touch("dispose")
        self.disposed = True

    def is_visible(self) -> bool:
        self._use()
        return True

    def is_enabled(self) -> bool:
        self._use()
        return True

    def is_editable(self) -> bool:
        self._use()
        if self.el.role != "textbox":
            raise base.Error("does not have a role allowing [aria-readonly]")
        return True

    def get_attribute(self, name: str) -> Optional[str]:
        self._use()
        return None

    def click(self, timeout: int = 0) -> None:
        self._use()
        self.el.clicks += 1
        if self.el.goes_to is not None:
            self._world.page.goto(self.el.goes_to)

    def fill(self, value: str, timeout: int = 0) -> None:
        self._use()
        self.el.value = value


class DomLocator(base._Obj):
    def __init__(self, world: base.World, page: "DomPage", role: str, name: Optional[str], index: Optional[int] = None) -> None:
        super().__init__(world)
        self.page, self.role, self.name, self.index = page, role, name, index

    def _matches(self) -> List[El]:
        found = [e for e in self.page.doc.elements if e.role == self.role and (self.name is None or e.name == self.name)]
        return found if self.index is None else found[self.index:self.index + 1]

    def count(self) -> int:
        self._world.touch("count")
        return len(self._matches())

    def nth(self, i: int) -> "DomLocator":
        return DomLocator(self._world, self.page, self.role, self.name, i)

    def aria_snapshot(self, **kw: Any) -> str:
        self._world.touch("aria_snapshot")
        (el,) = self._matches()
        return f'- {el.role} "{el.name}"'

    def element_handle(self, timeout: int = 0) -> Handle:
        self._world.touch("element_handle")
        (el,) = self._matches()
        return Handle(self._world, self.page.doc, el)


class DomPage(base.Page):
    def __init__(self, world: base.World) -> None:
        super().__init__(world)
        self.main_frame = Frame()
        self.doc = Doc(self.main_frame, [])
        world.page = self

    def goto(self, url: str, timeout: int = 0, wait_until: str = "load") -> None:
        super().goto(url, timeout=timeout, wait_until=wait_until)
        self.doc.alive = False                               # the old document (and every handle into it) is gone
        self.doc = Doc(self.main_frame, [El(e.role, e.name, e.goes_to) for e in self._world.site.get(url, [])])
        return None

    def get_by_role(self, role: str, name: Optional[str] = None, exact: bool = False, include_hidden: bool = False) -> DomLocator:
        return DomLocator(self._world, self, role, name)


class DomContext(base.Context):
    def new_page(self) -> DomPage:
        self._world.touch("new_page")
        page = DomPage(self._world)
        self.pages.append(page)
        return page


class DomBrowser(base.Browser):
    def new_context(self, **kw: Any) -> DomContext:
        self._world.touch("new_context")
        return DomContext(self._world)


class DomChromium(base.Chromium):
    def launch(self, **kw: Any) -> DomBrowser:
        self._world.touch("launch")
        return DomBrowser(self._world)


class DomPlaywright(base.Playwright):
    def __init__(self, world: base.World) -> None:
        super().__init__(world)
        self.chromium = DomChromium(world)


class DomManager(base.Manager):
    def start(self) -> DomPlaywright:
        super().start()
        return DomPlaywright(self._world)


class FakeDomApi(base.FakeSyncApi):
    """``site`` maps a URL to the elements of the document it serves."""

    def __init__(self, site: Dict[str, List[El]]) -> None:
        super().__init__()
        self.world.site = site
        self.world.session_closed = False
        self.world.page = None

    def sync_playwright(self) -> DomManager:
        return DomManager(self.world)
