# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""An optional detached signature over the manifest digest of a bundle: the statement that is signed, and the checks made with the operator's OpenSSH client (``ssh-keygen -Y``).

What this module does, and all of it:

* ``statement_bytes`` builds the bytes that are signed: canonical JSON naming the run id, the manifest digest and the plan digest. ``verify`` REBUILDS these bytes from the bundle it has just
  checked; it never reads a statement from a file the sender supplies.
* ``verify_signature`` checks a detached SSHSIG signature (namespace ``redevops-qa-anchor@v1``) over those bytes against ONE public key the verifying person supplied, by calling
  ``ssh-keygen -Y verify`` with an ``allowed_signers`` file this module writes for that one key. A key found in the bundle, next to the signature or in a log is never consulted.
* ``sign_statement`` hands the statement to ``ssh-keygen -Y sign`` with a key path (or an agent) the operator names. THIS PACKAGE NEVER GENERATES, STORES OR READS A PRIVATE KEY: the path is
  passed to ``ssh-keygen`` as an argument and nothing else. Keys are the operator's.

Fail closed: a missing, too old, unresponsive or unexpected ``ssh-keygen`` is state ``unavailable`` (exit status 7), never ``verified``. Only the exit status of ``ssh-keygen`` and one line of its
output that must match what this module expects decide ``verified``; a bad signature is state ``invalid`` (exit status 5).

What a ``verified`` result shows is in ``TRUST_STATEMENT``; what it does not show is in the same sentence. A signature carries no time and proves nothing about who holds the key."""
from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

from qa_evidence.canon import dumps_canonical, safe_text

from .safe_read import UnsafeRead, read_regular

NAMESPACE = "redevops-qa-anchor@v1"          # SSHSIG namespace: the domain separation from every other use of the same key
PRINCIPAL = "redevops-qa-anchor"             # the fixed principal of the one-line allowed_signers file this module writes
STATEMENT_SCHEMA = "redevops-qa/anchor-statement"
STATEMENT_VERSION = "1.0"
KEY_TYPE = "ssh-ed25519"                     # the only key type accepted in R0
MAX_SIGNATURE_BYTES = 4096
MAX_PUBLIC_KEY_BYTES = 2048
TOOL_NAME = "ssh-keygen"
TOOL_SEARCH_PATH = "/usr/bin:/bin"           # the same fixed PATH every child of this package gets (procs.child_env)
VERIFY_SECONDS = 20.0
AGENT_VARIABLES = ("SSH_AUTH_SOCK", "SSH_AGENT_PID")
SIGN_SECONDS = 300.0                         # a passphrase or a touch may be asked for

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RUN_ID_TEXT_RE = re.compile(r"^[\x21-\x7e]{1,64}$")
FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
PUBLIC_KEY_LINE_RE = re.compile(r"^ssh-ed25519 ([A-Za-z0-9+/]{68}) ?([\x20-\x7e]{0,200})$")

#: states of the signature check
ABSENT, VERIFIED, INVALID, UNAVAILABLE = "absent", "verified", "invalid", "unavailable"

TRUST_STATEMENT = ("The manifest digest of this evidence bundle (run {run_id}, plan digest {plan_digest}) carries a valid OpenSSH Ed25519 signature made with the private key belonging to the public key "
                   "with fingerprint {fingerprint}, which was supplied to this verification. A bundle rewritten after signing would not verify. This does not show who holds that key, that the key was "
                   "not exposed, when the signature was made, that the run was executed on an uncompromised host, or that the application under test is correct.")
ABSENT_NOTICE = "no signature was supplied: the manifest digest is not covered by a signature"


class AnchorSigError(Exception):
    """``state`` is ``invalid`` (the material is wrong: refuse it) or ``unavailable`` (the OpenSSH client cannot answer here: nothing is accepted, and nothing is learnt about the bundle)."""

    def __init__(self, state: str, message: str):
        super().__init__(message)
        self.state = state
        self.message = message


@dataclass(frozen=True)
class PublicKey:
    blob: bytes
    comment: str

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self.blob)

    def allowed_signers_line(self) -> str:
        """The one line of the ``allowed_signers`` file: a fixed principal, the namespace this signature must have been made in, the key. The comment is dropped; no option other than ``namespaces`` exists."""
        return f'{PRINCIPAL} namespaces="{NAMESPACE}" {KEY_TYPE} {base64.b64encode(self.blob).decode("ascii")}\n'


@dataclass(frozen=True)
class SignatureResult:
    state: str
    fingerprint: Optional[str] = None
    message: str = ""


def fingerprint_of(blob: bytes) -> str:
    """The OpenSSH SHA256 fingerprint of a public key blob (what ``ssh-keygen -l`` prints)."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def statement_bytes(run_id: str, manifest_digest: str, plan_digest: str) -> bytes:
    """The exact bytes that are signed. Every field is checked, so a statement is never made of a value that is not what it claims to be."""
    if not isinstance(run_id, str) or not RUN_ID_TEXT_RE.fullmatch(run_id):
        raise AnchorSigError(INVALID, "the run id is not 1 to 64 printable characters")
    for name, value in (("manifest digest", manifest_digest), ("plan digest", plan_digest)):
        if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
            raise AnchorSigError(INVALID, f"the {name} is not a sha256 digest")
    return dumps_canonical({"schema": STATEMENT_SCHEMA, "schema_version": STATEMENT_VERSION, "run_id": run_id, "manifest_digest": manifest_digest, "plan_digest": plan_digest})


def parse_public_key(data: bytes) -> PublicKey:
    """One OpenSSH public key line of type ssh-ed25519 and nothing else: no options in front (``command=``, ``cert-authority``...), no second line, no certificate, no other key type."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise AnchorSigError(INVALID, "the public key file is not one line of ASCII text") from None
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    match = PUBLIC_KEY_LINE_RE.fullmatch(text)
    if match is None:
        raise AnchorSigError(INVALID, f"the public key file is not one 'ssh-ed25519 <key>' line (only that key type is accepted; no options, no certificates): {safe_text(text.split(' ')[0], 40)!r}")
    blob = base64.b64decode(match.group(1), validate=True)
    expected = struct.pack(">I", len(KEY_TYPE)) + KEY_TYPE.encode() + struct.pack(">I", 32)
    if len(blob) != len(expected) + 32 or not blob.startswith(expected):
        raise AnchorSigError(INVALID, "the public key is not a well-formed ssh-ed25519 key")
    return PublicKey(blob, match.group(2))


def read_small(path: str, limit: int, what: str) -> bytes:
    """A regular file of at most ``limit`` bytes, opened without following a symbolic link (a FIFO, a device, a link, an oversized file is refused)."""
    try:
        return read_regular(path, max_bytes=limit, deadline_s=10.0, follow_symlinks=False)
    except UnsafeRead as exc:
        raise AnchorSigError(INVALID, f"the {what} cannot be used: {safe_text(exc.code, 30)} ({safe_text(str(exc), 60)})") from None


def tool_path() -> Optional[str]:
    return shutil.which(TOOL_NAME, path=TOOL_SEARCH_PATH)


def _require_tool() -> str:
    found = tool_path()
    if found is None:
        raise AnchorSigError(UNAVAILABLE, f"the OpenSSH client program '{TOOL_NAME}' was not found in {TOOL_SEARCH_PATH}: a signature cannot be checked here, and nothing is accepted")
    return found


def _run_tool(argv, data: bytes, *, cwd: Optional[str], env, timeout: float, own_session: bool) -> "subprocess.CompletedProcess":
    """``own_session`` for the check (no terminal, no agent, a clean environment); not for signing, where ``ssh-keygen`` may have to ask the operator for a passphrase on the terminal."""
    try:
        return subprocess.run(argv, input=data, capture_output=True, cwd=cwd, env=env, timeout=timeout, start_new_session=own_session, close_fds=True)
    except subprocess.TimeoutExpired:
        raise AnchorSigError(UNAVAILABLE, f"'{TOOL_NAME}' did not answer within {timeout:g} seconds: nothing is accepted") from None
    except OSError as exc:
        raise AnchorSigError(UNAVAILABLE, f"'{TOOL_NAME}' could not be run ({type(exc).__name__}): nothing is accepted") from None


def verify_signature(statement: bytes, signature_path: str, public_key_path: str) -> SignatureResult:
    """Check the signature file against the REBUILT ``statement`` and the one public key supplied. Never raises for a bad signature: that is ``invalid``; ``unavailable`` means the tool could not answer.

    ``ssh-keygen -Y verify`` exits 0 for a good signature and 255 for a signature it checked and refused (wrong key, wrong namespace, other statement, malformed); an OpenSSH client without ``-Y``
    (before 8.0) prints its usage and exits 1, which is ``unavailable`` here, like every other exit status."""
    try:
        sig = read_small(signature_path, MAX_SIGNATURE_BYTES, "signature file")
        _expect_key(sig)
        key = parse_public_key(read_small(public_key_path, MAX_PUBLIC_KEY_BYTES, "public key file"))
        tool = _require_tool()
        work = tempfile.mkdtemp(prefix="redevops-qa-anchor-")
    except AnchorSigError as exc:
        return SignatureResult(exc.state, None, exc.message)
    except OSError as exc:
        return SignatureResult(UNAVAILABLE, None, f"a temporary directory cannot be made ({type(exc).__name__}): nothing is accepted")
    try:
        os.chmod(work, 0o700)
        allowed, sigfile = os.path.join(work, "allowed_signers"), os.path.join(work, "statement.sig")
        for path, content in ((allowed, key.allowed_signers_line().encode("ascii")), (sigfile, sig)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(content)
        argv = [tool, "-Y", "verify", "-f", allowed, "-I", PRINCIPAL, "-n", NAMESPACE, "-s", sigfile]
        try:
            done = _run_tool(argv, statement, cwd=work, env={"PATH": TOOL_SEARCH_PATH, "HOME": work, "LANG": "C"}, timeout=VERIFY_SECONDS, own_session=True)
        except AnchorSigError as exc:
            return SignatureResult(exc.state, None, exc.message)
        except OSError as exc:
            return SignatureResult(UNAVAILABLE, None, f"the signature files cannot be written ({type(exc).__name__}): nothing is accepted")
        good = f'Good "{NAMESPACE}" signature for {PRINCIPAL} with ED25519 key {key.fingerprint}'
        if done.returncode == 0:
            if done.stdout.decode("ascii", "replace").strip() == good:
                return SignatureResult(VERIFIED, key.fingerprint, "")
            return SignatureResult(UNAVAILABLE, None, f"'{TOOL_NAME}' exited 0 but did not say what a good signature of this key says: nothing is accepted")
        if done.returncode == 255:
            return SignatureResult(INVALID, None, "the signature is not a valid signature of this bundle's statement by the supplied key in the namespace " + NAMESPACE)
        return SignatureResult(UNAVAILABLE, None, f"'{TOOL_NAME} -Y verify' exited with status {done.returncode} (an OpenSSH client older than 8.0 has no -Y): a signature cannot be checked here, and nothing is accepted")
    except OSError as exc:
        return SignatureResult(UNAVAILABLE, None, f"the signature check could not be set up ({type(exc).__name__}): nothing is accepted")
    finally:
        shutil.rmtree(work, ignore_errors=True)


ARMOR_BEGIN, ARMOR_END = "-----BEGIN SSH SIGNATURE-----", "-----END SSH SIGNATURE-----"
ARMOR_BODY_RE = re.compile(r"^[A-Za-z0-9+/=]{1,76}$")


def parse_signature(armored: bytes):
    """The key type, the public key blob and the namespace named inside an armored SSHSIG, and nothing else may be in the file: exactly the BEGIN line, base64 lines, the END line (LF only, one optional
    final newline). This reads only what is needed to refuse a signature early and by name (another key type, another namespace); whether the signature is VALID is ``ssh-keygen``'s answer alone."""
    try:
        lines = armored.decode("ascii").split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        if len(lines) < 3 or lines[0] != ARMOR_BEGIN or lines[-1] != ARMOR_END or not all(ARMOR_BODY_RE.fullmatch(l) for l in lines[1:-1]):
            raise ValueError("armor")
        raw = base64.b64decode("".join(lines[1:-1]), validate=True)
        if not raw.startswith(b"SSHSIG"):
            raise ValueError("magic")
        pos = 6 + 4                                         # magic, version

        def take():
            nonlocal pos
            (n,) = struct.unpack(">I", raw[pos:pos + 4])
            item = raw[pos + 4:pos + 4 + n]
            if len(item) != n:
                raise ValueError("short")
            pos += 4 + n
            return item
        blob, namespace = take(), take()
        (n,) = struct.unpack(">I", blob[:4])
        return blob[4:4 + n].decode("ascii"), blob, namespace.decode("ascii")
    except (ValueError, struct.error, UnicodeDecodeError):
        raise AnchorSigError(INVALID, "the signature file is not one armored OpenSSH signature (BEGIN line, base64, END line, nothing else)") from None


def _expect_key(armored: bytes) -> bytes:
    """The public key blob of a signature of the accepted key type, or a refusal by name. (The namespace is not compared here: ``ssh-keygen -Y sign`` is given ``-n`` and ``-Y verify`` is given ``-n`` and an
    ``allowed_signers`` line that carries ``namespaces=``, and a signature in another namespace is refused by it, which a test shows with the real tool.)"""
    key_type, blob, _namespace = parse_signature(armored)
    if key_type != KEY_TYPE:
        raise AnchorSigError(INVALID, f"the signature was made by a key of type {safe_text(key_type, 40)!r}: only {KEY_TYPE} is accepted")
    return blob


def sign_statement(statement: bytes, key_path: str, *, agent: bool = False) -> "tuple[bytes, str]":
    """Ask the operator's ``ssh-keygen -Y sign`` for a signature of ``statement``. ``key_path`` is only handed to ``ssh-keygen`` (with ``agent``: the PUBLIC key file, and the ssh-agent named by the
    environment signs). Returns the armored signature and the fingerprint of the key that made it. A signature by any other key type, or in another namespace, is refused."""
    tool = _require_tool()
    argv = [tool, "-Y", "sign", "-n", NAMESPACE, "-f", key_path] + (["-U"] if agent else [])
    env = dict(os.environ)                      # the operator's own environment (a terminal, an askpass program) ...
    if not agent:
        for name in AGENT_VARIABLES:           # ... but an ssh-agent only when the operator asked for one: ssh-keygen would otherwise offer the named key to an inherited agent
            env.pop(name, None)
    done = _run_tool(argv, statement, cwd=None, env=env, timeout=SIGN_SECONDS, own_session=False)
    if done.returncode != 0:
        raise AnchorSigError(INVALID, f"'{TOOL_NAME} -Y sign' failed with status {done.returncode}: " + safe_text(done.stderr.decode("utf-8", "replace").strip().splitlines()[-1] if done.stderr.strip() else "no message", 160))
    try:
        blob = _expect_key(done.stdout)
    except AnchorSigError as exc:
        raise AnchorSigError(INVALID, exc.message + "; nothing was written") from None
    return done.stdout, fingerprint_of(blob)
