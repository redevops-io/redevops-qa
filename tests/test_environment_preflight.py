# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""G0: the suite runs in a scrubbed environment (no credentials, throwaway HOME)."""
import os
import re
import tempfile
from pathlib import Path

_SENSITIVE = re.compile(r"TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL", re.IGNORECASE)
_CLOUD = ("GH_TOKEN", "GITHUB_TOKEN", "AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AZURE_CLIENT_ID", "GOOGLE_APPLICATION_CREDENTIALS")


def test_no_credential_like_variables():
    bad = sorted(name for name in os.environ if _SENSITIVE.search(name))
    assert not bad, f"credential-like variables in the environment: {bad}"


def test_no_cloud_profile_or_github_token():
    bad = [name for name in _CLOUD if name in os.environ]
    assert not bad, f"cloud or GitHub credentials present: {bad}"


def test_approval_secret_is_unset():
    assert "APPROVAL_SECRET" not in os.environ


def test_home_is_a_temporary_directory():
    home = Path(os.environ.get("HOME", "")).resolve()
    tmp_roots = {Path(tempfile.gettempdir()).resolve(), Path("/tmp").resolve(), Path("/private/tmp").resolve(),
                 Path("/var/folders").resolve(), Path("/private/var/folders").resolve()}
    assert any(root == home or root in home.parents for root in tmp_roots), f"HOME is not a temp directory: {home}"
