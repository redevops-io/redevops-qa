# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The interface's files carry nothing the policy forbids: no inline handler, no innerHTML or eval, no third-party URL, no inline script or style."""
import re
from pathlib import Path

UI = Path(__file__).resolve().parents[1] / "src" / "qa_service" / "ui"
FILES = sorted(p for p in UI.iterdir() if p.is_file())


def test_the_interface_has_the_files_it_needs_and_nothing_else():
    assert [p.name for p in FILES] == ["app.css", "app.js", "index.html"]


def test_no_forbidden_construct_in_any_interface_file():
    forbidden = [r"innerHTML", r"outerHTML", r"insertAdjacentHTML", r"document\.write", r"\beval\(", r"new Function", r"setTimeout\(\s*['\"]", r"\son[a-z]+\s*=\s*[\"']", r"javascript:", r"<script(?![^>]*\bsrc=)", r"<style", r"style\s*=\s*[\"']"]
    for f in FILES:
        text = f.read_text(encoding="utf-8")
        for pattern in forbidden:
            assert not re.search(pattern, text), f"{f.name}: {pattern}"


def test_no_third_party_url_font_or_image_and_every_load_is_same_origin():
    for f in FILES:
        text = f.read_text(encoding="utf-8")
        assert not re.search(r"https?://(?!127\.0\.0\.1|localhost)", re.sub(r"placeholder=\"http://127\.0\.0\.1:8203\"", "", text)), f.name
        assert "@import" not in text and "@font-face" not in text and "url(" not in text
    html = (UI / "index.html").read_text(encoding="utf-8")
    assert re.findall(r'(?:src|href)="([^"#]+)"', html) == ["/ui/app.css", "/ui/app.js"]
