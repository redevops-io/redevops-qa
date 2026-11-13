# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The product's own HTML report must fit a phone: the report of a real run, opened in real Chromium at 390 px (and at 1440 px), has no horizontal overflow of the page.
(It was 422 px wide at a 390 px viewport: a long sha256 in a table cell could not break.) The text is the report generator's; nothing here edits it."""
import json
from pathlib import Path

import pytest

from qa_runner.cli import main


def make_report(tmp_path: Path, capsys, defect: str) -> Path:
    out = tmp_path / "evidence"
    plan = Path(__file__).resolve().parents[2] / "examples" / "golden-plan.json"
    code = main(["run", str(plan), "--out", str(out), "--run-id", "layout-" + defect, "--defect", defect])
    assert code in (0, 1), capsys.readouterr()
    html = tmp_path / f"report-{defect}.html"
    assert main(["report", str(out / ("layout-" + defect)), "--format", "html", "-o", str(html)]) in (0, 1)
    assert "<table" in html.read_text(encoding="utf-8")
    return html


@pytest.mark.parametrize("defect", ["none", "settings"])
@pytest.mark.parametrize("width,height", [(390, 844), (360, 740), (1440, 900)])
def test_the_report_has_no_horizontal_overflow(tmp_path, capsys, defect, width, height):
    from playwright.sync_api import sync_playwright
    html = make_report(tmp_path, capsys, defect)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            page = browser.new_page(viewport={"width": width, "height": height})
            page.goto(html.as_uri())
            scroll = page.evaluate("document.documentElement.scrollWidth")
            wide = page.evaluate("[...document.querySelectorAll('body *')].filter(e => e.getBoundingClientRect().right > window.innerWidth + 1).slice(0, 5).map(e => e.tagName + ':' + (e.textContent || '').slice(0, 40))")
        finally:
            browser.close()
    assert scroll <= width and not wide, json.dumps({"viewport": width, "scrollWidth": scroll, "elements past the right edge": wide})
