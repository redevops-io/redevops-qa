# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""P1-4 CI hardening, as a standing test: every action reference in every workflow is pinned to a full commit
SHA (the audit's grep `uses: [^@]+@[a-z0-9.]+$` must stay empty), and the Dependabot configuration exists and
covers the ecosystems this repository installs from. A tag reference can move under CI's feet without a commit
in this repository changing; a 40-hex reference cannot."""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
USES_RE = re.compile(r"^\s*-?\s*uses:\s*(\S+)", re.M)
# tag-only reference = the bit after @ is a human tag, never a full commit SHA
TAG_REF_RE = re.compile(r"uses: [^@\s]+@(?!([0-9a-f]{40})(\s|$))[a-z0-9.]+(?:\s|$|#)")


def test_every_workflow_exists_and_parses():
    assert {p.name for p in WORKFLOWS} >= {"tests.yml", "bundle.yml", "appium-android.yml"}
    for path in WORKFLOWS:
        assert yaml.safe_load(path.read_text(encoding="utf-8"))


def test_no_action_reference_is_tag_only_any_workflow():
    for path in WORKFLOWS:
        text = path.read_text(encoding="utf-8")
        assert not TAG_REF_RE.search(text), f"{path.name}: pin by commit SHA, not by tag"
        for ref in USES_RE.findall(text):
            action, _, sha = ref.partition("@")
            assert action != ".", "local action references would need the same care"
            assert re.fullmatch(r"[0-9a-f]{40}", sha), f"{path.name}: {ref!r} is not pinned to a full SHA"


def test_dependabot_is_configured_for_actions_and_for_every_package_that_declares_dependencies():
    conf = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    assert conf["version"] == 2
    ecosystems = {u["package-ecosystem"] for u in conf["updates"]}
    assert {"github-actions", "pip"} <= ecosystems
    pip_dirs = set()
    for update in conf["updates"]:
        if update["package-ecosystem"] != "pip":
            continue
        dirs = update.get("directories") or ([] if "directory" not in update else [update["directory"]])
        pip_dirs.update(dirs)
    declared = {f"/packages/{p.parent.name}" for p in ROOT.glob("packages/*/pyproject.toml")
                if "dependencies" in p.read_text(encoding="utf-8")}
    assert declared <= pip_dirs, f"Dependabot misses: {sorted(declared - pip_dirs)}"