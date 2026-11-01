# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The README documents what the code does (defects, options, routes), every Python file carries the licence header, and the wording
of the licence is the repository's."""
import re

import qfa_support as s

from qa_fixture_app import DEFECT_DESCRIPTIONS, DEFECTS
from qa_fixture_app.cli import build_parser

README = (s.PKG / "README.md").read_text(encoding="utf-8")
HEADER = "# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause"


def test_every_python_file_has_the_spdx_header_first():
    files = [p for p in s.PKG.rglob("*.py") if "__pycache__" not in p.parts]
    assert len(files) >= 12
    for path in files:
        assert path.read_text(encoding="utf-8").splitlines()[0] == HEADER, path


def test_the_readme_documents_every_defect_and_every_option():
    for name in DEFECTS:
        assert "`%s`" % name in README
    for action in build_parser()._actions:
        for flag in action.option_strings:
            if flag.startswith("--") and flag not in ("--help",):
                assert flag in README, flag


def test_the_readme_lists_every_route_the_app_serves():
    from qa_fixture_app import FixtureApp
    paths = set(FixtureApp()._routes) | {"/api/orders/<id>", "/orders/<id>"}
    for path in paths:
        assert ("`GET %s" % path in README) or ("%s`" % path in README) or ("%s," % path in README) or (" %s " % path in README), path
    assert "10 percent" in README


def test_licence_wording_is_the_repositorys_and_makes_no_open_source_claim():
    assert "source-available" in README and "LICENSE.md" in README
    text = (s.PKG / "pyproject.toml").read_text(encoding="utf-8")
    assert 'license = { text = "LicenseRef-AGPL-3.0-or-later-with-Commons-Clause" }' in text and "dependencies = []" in text
    assert not re.search(r"(?<!not )open[- ]source", README, re.I)


def test_the_defect_descriptions_are_in_the_documented_wording_of_the_readme_table():
    assert DEFECT_DESCRIPTIONS["discount"].startswith("The order discount rule is not applied")
    assert "acknowledged" in DEFECT_DESCRIPTIONS["settings"] and "nothing is stored" in DEFECT_DESCRIPTIONS["settings"]
