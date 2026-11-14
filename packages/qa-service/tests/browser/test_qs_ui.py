# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The interface in a real browser against the real service: sign in, the availability states, target registration, an estimate, a run that waits for approval and is approved, the evidence and
its independent verification, the history, and the layout at 390 and 1440 px with no console error and no content-security-policy violation."""
import os
import re
from pathlib import Path

import pytest

from qa_service.capabilities import Facts
from qa_service.runs import wait_idle

PASSWORD = "correct horse battery staple"
SHOTS = os.environ.get("QA_UI_SHOTS")


class Page:
    def __init__(self, browser, base, width=1440, height=900):
        self.context = browser.new_context(viewport={"width": width, "height": height})
        self.page = self.context.new_page()
        self.base = base
        self.problems = []
        self.page.on("console", lambda m: self.problems.append(("console", m.type, m.text)) if m.type in ("error", "warning") else None)
        self.page.on("pageerror", lambda e: self.problems.append(("pageerror", str(e))))
        self.page.on("requestfailed", lambda r: self.problems.append(("requestfailed", r.url)) if "/evidence/files/" not in r.url else None)     # a download ends its navigation
        self.external = []
        self.page.on("request", lambda r: self.external.append(r.url) if not r.url.startswith(base) and not r.url.startswith("data:") else None)

    def goto(self, path):
        self.page.goto(self.base + path)
        return self

    def signin(self, name, password=PASSWORD):
        self.goto("/ui/")
        self.page.get_by_label("User name").fill(name)
        self.page.get_by_label("Password").fill(password)
        self.page.get_by_role("button", name="Sign in").click()
        self.page.get_by_role("heading", name="Dashboard").wait_for()
        return self

    def overflow(self):
        return self.page.evaluate("[document.documentElement.scrollWidth, window.innerWidth, [...document.querySelectorAll('body *')].filter(e => e.getBoundingClientRect().right > window.innerWidth + 1 && !e.closest('.scroll')).slice(0,5).map(e => e.tagName + ':' + (e.textContent||'').slice(0,30))]")

    def shot(self, name):
        if SHOTS:
            Path(SHOTS).mkdir(parents=True, exist_ok=True)
            self.page.screenshot(path=f"{SHOTS}/{name}.png", full_page=True)

    def close(self):
        self.context.close()


@pytest.fixture
def ui(make_server, browser):
    pages = []

    def make(width=1440, height=900, **kw):
        srv, c = make_server(**kw)
        for name, role in (("alice-admin", "admin"), ("olivia-op", "operator"), ("vince-view", "viewer")):
            srv.users.add(name, role, PASSWORD)
        pg = Page(browser, c.base, width, height)
        pages.append(pg)
        return srv, c, pg
    yield make
    for pg in pages:
        pg.close()


def no_problems(pg):
    assert pg.problems == [], pg.problems
    assert pg.external == [], "a request left this origin: " + str(pg.external)


def test_sign_in_failure_is_said_in_words_and_success_lands_on_the_dashboard(ui):
    srv, c, pg = ui()
    pg.goto("/ui/")
    assert pg.page.get_by_role("heading", name="Sign in").is_visible()
    pg.page.get_by_label("User name").fill("alice-admin")
    pg.page.get_by_label("Password").fill("wrong password here")
    pg.page.get_by_role("button", name="Sign in").click()
    pg.page.get_by_role("alert").wait_for()
    assert "wrong" in pg.page.get_by_role("alert").inner_text()
    assert [p for p in pg.problems if "401" not in str(p)] == [], "the one expected console line is the browser's note of the 401 itself"
    pg.problems.clear()
    pg.page.get_by_label("Password").fill(PASSWORD)
    pg.page.get_by_role("button", name="Sign in").click()
    pg.page.get_by_role("heading", name="Dashboard").wait_for()
    assert "alice-admin (admin)" in pg.page.locator("#who").inner_text()
    assert pg.page.get_by_text("This installation can run lanes.").is_visible()
    pg.page.get_by_role("button", name="Sign out").click()
    pg.page.get_by_role("heading", name="Sign in").wait_for()
    no_problems(pg)


def test_an_installation_that_cannot_run_lanes_says_so_everywhere_and_never_offers_a_dead_button(ui):
    srv, c, pg = ui(facts=Facts(machine="aarch64", missing_packages=("playwright", "robot")))
    pg.signin("olivia-op")
    assert pg.page.get_by_text("No lane can run on this installation.").is_visible()
    assert "ARCHITECTURE_UNSUPPORTED" in pg.page.locator("main").inner_text() and "Remedy:" in pg.page.locator("main").inner_text()
    pg.shot("unavailable-dashboard-1440")
    pg.page.get_by_role("link", name="New run").click()
    pg.page.get_by_role("heading", name="New run").wait_for()
    assert pg.page.get_by_role("button", name="Estimate").is_disabled() and pg.page.get_by_role("button", name="Start run").is_disabled()
    text = pg.page.locator("main").inner_text()
    assert "unavailable because" in text and "linux x86_64 only" in text and "No profile can run against this target here" in text
    no_problems(pg)


def test_the_whole_workflow_in_the_browser_register_estimate_approve_run_inspect_verify(ui):
    srv, c, pg = ui()
    pg.signin("alice-admin")
    pg.page.get_by_role("link", name="Targets").click()
    pg.page.get_by_label("Name").fill("fixture with approval")
    pg.page.get_by_label("Require approval for runs against a fixture-app target").check()
    pg.page.get_by_role("button", name="Register target").click()
    pg.page.get_by_text("fixture with approval").first.wait_for()
    pg.page.get_by_role("link", name="New run").click()
    pg.page.get_by_label("Target", exact=True).select_option(label="fixture with approval (fixture-app)")
    pg.page.get_by_label("Test profile", exact=True).select_option("fixture-browser")
    assert pg.page.get_by_role("button", name="Start run").is_disabled(), "an approval target needs an estimate first"
    pg.page.get_by_role("button", name="Estimate").click()
    pg.page.get_by_text("Nothing in the estimate stops a run.").wait_for()
    assert pg.page.get_by_text("sha256:").first.is_visible()
    pg.page.get_by_role("button", name="Start run").click()
    pg.page.get_by_text("Waiting for approval.").wait_for()
    run_id = re.search(r"r\d{8}T\d{6}Z-[0-9a-f]{6}", pg.page.url).group(0)
    pg.shot("run-awaiting-approval-1440")
    pg.page.get_by_label("Reason (optional)").fill("reviewed the estimate")
    pg.page.get_by_role("button", name="Approve").click()
    assert wait_idle(srv.store, 30)
    pg.page.get_by_text("Approval: approved by alice-admin").wait_for(timeout=15000)
    pg.page.get_by_text("VERIFIED", exact=True).first.wait_for(timeout=15000)
    body = pg.page.locator("main").inner_text()
    assert "run.approved" in body and "run.finished" in body and "Approval: approved by alice-admin (admin, session)" in body
    pg.shot("run-finished-1440")
    pg.page.get_by_role("link", name="Evidence and verification").click()
    pg.page.get_by_text("Independent verification:").wait_for()
    assert "bundle-manifest.json" in pg.page.locator("main").inner_text() and "VERIFIED" in pg.page.locator(".banner").first.inner_text()
    with pg.page.expect_download() as dl:
        pg.page.get_by_role("link", name="Download").nth(1).click()
    assert dl.value.suggested_filename == "x.txt"
    pg.shot("evidence-1440")
    pg.page.get_by_role("link", name="Runs", exact=True).click()
    pg.page.get_by_role("link", name=run_id).wait_for()
    pg.page.get_by_label("Outcome").select_option("FAILED")
    pg.page.get_by_role("button", name="Filter").click()
    pg.page.get_by_text("No run matches.").wait_for()
    no_problems(pg)


def test_roles_are_visible_in_the_interface_a_viewer_cannot_start_or_register(ui):
    srv, c, pg = ui()
    pg.signin("vince-view")
    pg.page.get_by_role("link", name="Targets").click()
    pg.page.get_by_text("Registering targets needs the admin role.").wait_for()
    assert pg.page.get_by_role("link", name="Users").count() == 0
    pg.page.get_by_role("link", name="New run").click()
    pg.page.get_by_role("button", name="Start run").click()
    pg.page.get_by_role("alert").wait_for()
    assert "operator role" in pg.page.get_by_role("alert").inner_text()


def test_the_external_edge_sentinel_profile_is_listed_unavailable_with_its_reason(ui):
    srv, c, pg = ui()
    pg.signin("olivia-op")
    assert "EXTERNAL_RUN_NOT_ENABLED" in pg.page.locator("main").inner_text()
    assert "Edge Sentinel fixture mode (read-only)" in pg.page.locator("main").inner_text()


@pytest.mark.parametrize("width,height", [(1440, 900), (390, 844)])
def test_every_view_fits_the_viewport_without_a_console_error_or_a_foreign_request(ui, width, height):
    srv, c, pg = ui(width=width, height=height)
    pg.signin("alice-admin")
    run = c.json("POST", "/v1/runs", {"plan": "browser"})[1]
    assert wait_idle(srv.store, 20)
    for path, heading in (("/ui/", "Dashboard"), ("/ui/targets", "Targets"), ("/ui/new", "New run"), ("/ui/runs", "Runs"), ("/ui/users", "Users"), ("/ui/about", "About"),
                          (f"/ui/runs/{run['id']}", f"Run {run['id']}"), (f"/ui/runs/{run['id']}/evidence", f"Evidence of {run['id']}")):
        pg.goto(path)
        pg.page.get_by_role("heading", name=heading).wait_for()
        scroll, inner, wide = pg.overflow()
        assert scroll <= inner and not wide, (path, scroll, inner, wide)
        pg.shot(f"{heading.split()[0].lower()}-{width}")
    no_problems(pg)


def test_keyboard_users_get_a_skip_link_a_focused_heading_and_labelled_controls(ui):
    srv, c, pg = ui()
    pg.goto("/ui/")
    pg.page.keyboard.press("Tab")
    assert pg.page.evaluate("document.activeElement.textContent") == "Skip to content"
    pg.page.get_by_label("User name").fill("alice-admin")
    pg.page.get_by_label("Password").fill(PASSWORD)
    pg.page.keyboard.press("Enter")
    pg.page.get_by_role("heading", name="Dashboard").wait_for()
    assert pg.page.evaluate("document.activeElement.id") == "title"
    assert pg.page.evaluate("[...document.querySelectorAll('input,select,textarea')].filter(e => !e.labels || !e.labels.length).length") == 0
    assert pg.page.evaluate("document.querySelectorAll('main,nav,header').length") == 3
    assert pg.page.evaluate("[...document.querySelectorAll('.scroll')].every(e => e.tabIndex === 0 && e.getAttribute('role') === 'region')")


def test_the_report_page_the_product_generates_opens_as_its_own_document_without_script(ui):
    srv, c, pg = ui()
    pg.signin("olivia-op")
    run = c.json("POST", "/v1/runs", {"plan": "browser"})[1]
    assert wait_idle(srv.store, 20)
    resp = pg.page.request.get(pg.base + f"/v1/runs/{run['id']}/report?format=html")
    assert resp.status == 200 and "default-src 'none'" in resp.headers["content-security-policy"] and "<script" not in resp.text()
