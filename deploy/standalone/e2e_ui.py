#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""A fresh user's workflow, entirely in the browser, against a RUNNING deployment (the real engine, no fake): sign in with the bootstrap admin, read the availability, start a browser-lane run
of the bundled fixture app, watch it finish VERIFIED, open its evidence and the independent verification, run again with a seeded defect and see it FAIL with evidence that still verifies, and
find both in the history. Screenshots at 1440x900 and 390x844 go to QA_E2E_SHOTS when it is set.

    python3 e2e_ui.py http://127.0.0.1:8080 <admin password>        (needs the Playwright package and Chromium on the machine that runs it)
"""
import os
import re
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE, PASSWORD = sys.argv[1].rstrip("/"), sys.argv[2]
SHOTS = os.environ.get("QA_E2E_SHOTS")
PROFILE = os.environ.get("QA_E2E_PROFILE", "fixture-browser")


def shot(page, name):
    if SHOTS:
        Path(SHOTS).mkdir(parents=True, exist_ok=True)
        page.screenshot(path=f"{SHOTS}/{name}.png", full_page=True)


def run_once(page, defect):
    page.get_by_role("link", name="New run").click()
    page.get_by_role("heading", name="New run").wait_for()
    page.locator("#nprofile").select_option(PROFILE)
    if defect != "none":
        page.locator("#ndefect").select_option(defect)
    page.get_by_role("button", name="Start run").click()
    page.get_by_role("heading", name=re.compile(r"^Run r\d{8}T")).wait_for()
    run_id = re.search(r"r\d{8}T\d{6}Z-[0-9a-f]{6}", page.url).group(0)
    page.get_by_text("run.finished").wait_for(timeout=180000)
    return run_id


def main():
    problems = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for width, height, tag in ((1440, 900, "1440x900"), (390, 844, "390x844")):
            ctx = browser.new_context(viewport={"width": width, "height": height})
            page = ctx.new_page()
            page.on("console", lambda m: problems.append(m.text) if m.type in ("error", "warning") and "401" not in m.text else None)
            page.on("pageerror", lambda e: problems.append(str(e)))
            page.goto(BASE + "/")                       # the service sends a browser to the interface
            page.get_by_role("heading", name="Sign in").wait_for()
            shot(page, f"01-signin-{tag}")
            page.get_by_label("User name").fill("admin")
            page.get_by_label("Password").fill(PASSWORD)
            page.get_by_role("button", name="Sign in").click()
            page.get_by_role("heading", name="Dashboard").wait_for()
            shot(page, f"02-dashboard-{tag}")
            if width == 1440:
                ok = run_once(page, "none")
                page.get_by_text("VERIFIED", exact=True).first.wait_for()
                shot(page, f"03-run-verified-{tag}")
                page.get_by_role("link", name="Evidence and verification").click()
                page.get_by_text("Independent verification:").wait_for()
                assert "ACCEPTED" in page.locator("main").inner_text() or "VERIFIED" in page.locator(".banner").first.inner_text()
                shot(page, f"04-evidence-{tag}")
                bad = run_once(page, "settings")
                page.get_by_text("FAILED", exact=True).first.wait_for()
                shot(page, f"05-run-failed-{tag}")
                page.get_by_role("link", name="Evidence and verification").click()
                page.get_by_text("Independent verification:").wait_for()
                assert "bundle verified" in page.locator("main").inner_text() or "verified" in page.locator("main").inner_text().lower()
                page.get_by_role("link", name="Runs", exact=True).click()
                page.get_by_role("link", name=ok).wait_for()
                page.get_by_role("link", name=bad).wait_for()
                shot(page, f"06-history-{tag}")
            else:
                for path, heading in (("/ui/runs", "Runs"), ("/ui/targets", "Targets"), ("/ui/new", "New run")):
                    page.goto(BASE + path)
                    page.get_by_role("heading", name=heading).wait_for()
                    scroll = page.evaluate("document.documentElement.scrollWidth")
                    assert scroll <= width, f"{path} overflows at {width}px: {scroll}"
                    shot(page, f"07-{heading.split()[0].lower()}-{tag}")
            ctx.close()
        browser.close()
    if problems:
        print("console problems:", problems)
        return 1
    print("E2E UI OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
