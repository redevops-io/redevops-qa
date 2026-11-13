# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Configuration of the service, read from environment variables. The service has no default credential: without a usable token it does not start."""
from __future__ import annotations

import ipaddress
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional

MIN_TOKEN_LENGTH = 32
MAX_TOKEN_LENGTH = 512
TOKEN_CHARS = re.compile(r"^[A-Za-z0-9._~+/=-]+$")
#: words that mark a value somebody copied from documentation instead of generating one
PLACEHOLDER_MARKS = ("changeme", "change-me", "change_me", "example", "placeholder", "replace", "your-token", "yourtoken", "insert", "todo", "password", "default")

ENV_TOKEN = "QA_SERVICE_TOKEN"
ENV_TOKEN_FILE = "QA_SERVICE_TOKEN_FILE"
ENV_BIND = "QA_SERVICE_BIND"
ENV_PORT = "QA_SERVICE_PORT"
ENV_DATA = "QA_SERVICE_DATA_DIR"
ENV_CLI = "QA_SERVICE_CLI"
ENV_PLANS = "QA_SERVICE_PLANS_DIR"
ENV_TIMEOUT = "QA_SERVICE_RUN_TIMEOUT"


class ConfigError(Exception):
    """The configuration cannot be used; the message never contains the token."""


@dataclass(frozen=True)
class Config:
    token: bytes
    bind: str
    port: int
    data_dir: Path
    cli: str
    plans_dir: Optional[Path]
    run_timeout: int
    max_body: int = 4096
    request_timeout: int = 30


def token_problem(token: str) -> Optional[str]:
    """Why a token is refused, or None. The reason names the rule, never the value."""
    if len(token) < MIN_TOKEN_LENGTH:
        return f"shorter than {MIN_TOKEN_LENGTH} characters"
    if len(token) > MAX_TOKEN_LENGTH:
        return f"longer than {MAX_TOKEN_LENGTH} characters"
    if not TOKEN_CHARS.fullmatch(token):
        return "contains a character outside A-Z a-z 0-9 . _ ~ + / = - (no spaces, no quotes)"
    if len(set(token)) < 8:
        return "has fewer than 8 distinct characters"
    low = token.lower()
    for mark in PLACEHOLDER_MARKS:
        if mark in low:
            return "looks like a placeholder taken from documentation"
    return None


def _read_token(env: Mapping[str, str]) -> str:
    direct, path = env.get(ENV_TOKEN), env.get(ENV_TOKEN_FILE)
    if direct and path:
        raise ConfigError(f"set {ENV_TOKEN} or {ENV_TOKEN_FILE}, not both")
    if path:
        try:
            raw = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"{ENV_TOKEN_FILE} cannot be read ({type(exc).__name__})") from None
        except UnicodeDecodeError:
            raise ConfigError(f"{ENV_TOKEN_FILE} is not text") from None
        return raw.strip("\r\n")
    if direct:
        return direct
    raise ConfigError(f"no token: set {ENV_TOKEN_FILE} (a file holding the token, for example a mounted secret) or {ENV_TOKEN}; the service has no default credential "
                      "and does not start without one (generate one with: openssl rand -hex 32)")


def _int(env: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw, 10)
    except ValueError:
        raise ConfigError(f"{name} is not a whole number") from None
    if not low <= value <= high:
        raise ConfigError(f"{name} must be between {low} and {high}")
    return value


def load_config(env: Mapping[str, str]) -> Config:
    token = _read_token(env)
    problem = token_problem(token)
    if problem:
        raise ConfigError(f"the token is refused: {problem} (generate one with: openssl rand -hex 32)")
    bind = env.get(ENV_BIND, "127.0.0.1")
    try:
        ipaddress.ip_address(bind)
    except ValueError:
        raise ConfigError(f"{ENV_BIND} must be an IP address (default 127.0.0.1)") from None
    port = _int(env, ENV_PORT, 8080, 0, 65535)
    data = env.get(ENV_DATA, "")
    if not data or not data.startswith("/"):
        raise ConfigError(f"{ENV_DATA} must be an absolute path to a directory the service may write")
    cli = env.get(ENV_CLI, "redevops-qa")
    resolved = shutil.which(cli)
    if resolved is None:
        raise ConfigError(f"the redevops-qa command was not found ({ENV_CLI}={cli!r})")
    plans = env.get(ENV_PLANS)
    if plans is not None and not plans.startswith("/"):
        raise ConfigError(f"{ENV_PLANS} must be an absolute path")
    return Config(token=token.encode("ascii"), bind=bind, port=port, data_dir=Path(data), cli=resolved, plans_dir=Path(plans) if plans else None,
                  run_timeout=_int(env, ENV_TIMEOUT, 1800, 10, 86400))
