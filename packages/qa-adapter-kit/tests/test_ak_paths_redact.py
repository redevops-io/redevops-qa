# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
import os

import pytest

from ak_support import fresh_secret
from qa_adapter_kit import PathPolicy, PathRefused, Redactor, REDACTED, is_denied


@pytest.fixture
def policy(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    return PathPolicy([root]), root


def test_a_path_inside_a_root_resolves(policy):
    p, root = policy
    (root / "a").mkdir()
    assert p.resolve("a", base=root) == (root / "a").resolve()
    assert p.resolve(str(root / "a")) == (root / "a").resolve()


@pytest.mark.parametrize("rel", ["../x", "a/../../x", "..", "/etc/hosts", "/tmp"])
def test_a_path_outside_the_roots_is_refused(policy, rel):
    p, root = policy
    with pytest.raises(PathRefused):
        p.resolve(rel, base=root)


def test_a_symlink_that_leaves_the_root_is_refused(policy, tmp_path):
    p, root = policy
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "f").write_text("x")
    os.symlink(outside, root / "link")
    os.symlink(outside / "f", root / "flink")
    for name in ("link", "link/f", "flink"):
        with pytest.raises(PathRefused):
            p.resolve(name, base=root)


def test_a_symlink_that_stays_inside_is_fine(policy):
    p, root = policy
    (root / "real").mkdir()
    os.symlink(root / "real", root / "alias")
    assert p.resolve("alias", base=root) == (root / "real").resolve()


@pytest.mark.parametrize("path", ["/var/run/docker.sock", "/run/docker.sock", "/etc/passwd", "/proc/1/environ", "/sys/kernel", "/dev/mem",
                                  "/root/x", "/home/u/.ssh/id_rsa", "/home/u/.aws/credentials", "/home/u/.docker/config.json",
                                  "/home/u/.kube/config", "/srv/x/docker.sock", "/srv/x/id_ed25519", "/home/u/.netrc", "/x/.npmrc"])
def test_prohibited_locations(path):
    assert is_denied(path)


@pytest.mark.parametrize("path", ["/tmp/ws/suite", "/home/runner/work/x", "/usr/bin/python3", "/opt/tools/bin/run"])
def test_ordinary_locations_are_not_denied(path):
    assert not is_denied(path)


def test_a_root_on_the_prohibited_list_cannot_be_configured(tmp_path):
    for bad in ("/", "/etc", "/var/run", str(tmp_path / ".ssh")):
        with pytest.raises(PathRefused):
            PathPolicy([bad])
    with pytest.raises(PathRefused):
        PathPolicy([])


def test_the_deny_list_applies_inside_an_allowed_root(policy):
    p, root = policy
    (root / ".ssh").mkdir()
    (root / "docker.sock").write_text("")
    for name in (".ssh/id_rsa", ".ssh", "docker.sock"):
        with pytest.raises(PathRefused):
            p.resolve(name, base=root)


def test_a_nul_byte_and_a_relative_path_without_a_base_are_refused(policy):
    p, root = policy
    with pytest.raises(PathRefused):
        p.resolve("a\x00b", base=root)
    with pytest.raises(PathRefused):
        p.resolve("a")


def test_must_exist(policy):
    p, root = policy
    with pytest.raises(PathRefused):
        p.resolve("nothing", base=root, must_exist=True)
    assert p.resolve("nothing", base=root) == (root / "nothing").resolve()


# ---------------------------------------------------------------------------------------------- redaction
def test_a_known_secret_is_replaced_everywhere():
    s = fresh_secret()
    r = Redactor([s])
    assert r.text(f"a {s} b {s}") == f"a {REDACTED} b {REDACTED}"
    assert s not in r.data(f"line {s}".encode())


def test_credential_shaped_assignments_and_bearer_values_are_redacted_without_knowing_the_value():
    r = Redactor()
    for text in ("password=abc123xyz", "API_KEY: abcdef", "Authorization: Bearer abcdefgh12345678", "token = value-here", "MY_SECRET=zz"):
        out = r.text(text)
        assert REDACTED in out and "abc123xyz" not in out and "abcdefgh12345678" not in out and "value-here" not in out


def test_short_values_are_not_treated_as_secrets_to_avoid_mangling_text():
    assert Redactor(["ab"]).text("about") == "about" and not Redactor(["ab"]).active


def test_longer_secrets_are_replaced_before_their_prefixes():
    r = Redactor(["abcd", "abcdefgh"])
    assert r.text("x abcdefgh y") == f"x {REDACTED} y"


def test_a_secret_cannot_survive_as_a_fragment_at_the_cut():
    s = fresh_secret()
    out = Redactor([s]).data(("pad" * 100 + s + "end").encode(), limit=len(s) // 2 + 3 + 3)
    assert s[:6] not in out.replace(REDACTED, "")


def test_undecodable_bytes_do_not_fail():
    assert Redactor().data(b"\xff\xfe ok") .endswith("ok")
