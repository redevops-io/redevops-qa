# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The README names what the repository holds and nothing else: every package it lists exists, every package that exists is listed, what is absent is said to be absent, and every
relative link resolves. (An earlier README named four packages and a deploy directory that did not exist.)"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
PACKAGES = sorted(p.name for p in (ROOT / "packages").iterdir() if (p / "pyproject.toml").is_file())
NOT_HERE = README.split("**Not in this repository:**", 1)[1].split("\n\n", 1)[0] if "**Not in this repository:**" in README else ""
LAYOUT = README.split("## Layout", 1)[1]


def test_every_package_the_readme_lists_exists_and_every_package_is_listed():
    listed = re.search(r"Packages \(under `packages/`\): (.*?)\.\n", LAYOUT, re.S).group(1)
    names = re.findall(r"`(qa-[a-z-]+)`", listed)
    assert sorted(names) == PACKAGES and len(set(names)) == len(names)


def test_what_the_readme_names_as_absent_is_absent_and_said_so():
    assert NOT_HERE, "the README must say what is not in the repository"
    for name in ("qa-api", "qa-ui"):
        assert f"`{name}`" in NOT_HERE and not (ROOT / "packages" / name).exists()
    for path in ("deploy", "benchmarks", "examples"):
        assert not (ROOT / path).exists()
    assert "`deploy/`" in NOT_HERE and "benchmarks" in NOT_HERE


def test_no_package_is_named_outside_the_absent_list_unless_it_exists():
    absent = set(re.findall(r"`(qa-[a-z-]+)`", NOT_HERE))
    for name in set(re.findall(r"`(qa-[a-z-]+)`", README)):
        assert name in PACKAGES or name in absent, name


def test_every_relative_link_of_the_readme_resolves():
    for target in re.findall(r"\]\((?!https?://|#)([^)#]+)(?:#[^)]*)?\)", README):
        assert (ROOT / target).exists(), target


def test_the_readme_does_not_call_the_project_open_source_and_does_not_claim_other_platforms():
    low = README.lower()
    assert not re.search(r"(?<!not )open[- ]source", low) and "soc 2" not in low and "tamper-proof" not in low
    assert "macos and windows are not claimed" in low and "linux x86_64" in low
