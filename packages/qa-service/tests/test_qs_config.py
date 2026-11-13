# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The service has no default credential: without a usable token it does not start, and no message repeats the token."""
import subprocess
import sys

import pytest

from qa_service.config import ConfigError, load_config, token_problem

from qs_support import TOKEN, make_env


def test_no_token_no_start(tmp_path):
    env = make_env(tmp_path)
    del env["QA_SERVICE_TOKEN"]
    with pytest.raises(ConfigError, match="no token"):
        load_config(env)


@pytest.mark.parametrize("bad", ["", "tiny", "x" * 31, "a" * 40, "changeme-" + "Zx9Qw3Lm7Rk2Vb8Nc5Hd1Jf6Gs4Ap0Yu", "has space " + "Zx9Qw3Lm7Rk2Vb8Nc5Hd1Jf6Gs4Ap0Yu", "quote'" + "Zx9Qw3Lm7Rk2Vb8Nc5Hd1Jf6Gs4Ap0Yu", "A" * 600])
def test_weak_or_placeholder_tokens_are_refused_and_never_echoed(tmp_path, bad):
    env = make_env(tmp_path, QA_SERVICE_TOKEN=bad)
    with pytest.raises(ConfigError) as exc:
        load_config(env)
    assert bad not in str(exc.value) or bad == ""


def test_a_generated_token_is_accepted_from_a_file_and_the_trailing_newline_is_dropped(tmp_path):
    f = tmp_path / "token"
    f.write_text(TOKEN + "\n")
    env = make_env(tmp_path)
    del env["QA_SERVICE_TOKEN"]
    env["QA_SERVICE_TOKEN_FILE"] = str(f)
    assert load_config(env).token == TOKEN.encode()
    assert token_problem(TOKEN) is None


def test_token_and_file_together_are_refused(tmp_path):
    f = tmp_path / "token"
    f.write_text(TOKEN)
    with pytest.raises(ConfigError, match="not both"):
        load_config(make_env(tmp_path, QA_SERVICE_TOKEN_FILE=str(f)))


def test_unreadable_token_file_is_a_config_error(tmp_path):
    env = make_env(tmp_path)
    del env["QA_SERVICE_TOKEN"]
    env["QA_SERVICE_TOKEN_FILE"] = str(tmp_path / "absent")
    with pytest.raises(ConfigError, match="cannot be read"):
        load_config(env)


def test_defaults_bind_to_loopback_and_need_an_absolute_data_dir(tmp_path):
    env = make_env(tmp_path)
    del env["QA_SERVICE_BIND"]
    assert load_config(env).bind == "127.0.0.1"
    env["QA_SERVICE_DATA_DIR"] = "relative"
    with pytest.raises(ConfigError, match="absolute"):
        load_config(env)
    env = make_env(tmp_path, QA_SERVICE_BIND="not-an-ip")
    with pytest.raises(ConfigError, match="IP address"):
        load_config(env)


def test_port_and_timeout_are_bounded(tmp_path):
    for name, value in (("QA_SERVICE_PORT", "70000"), ("QA_SERVICE_PORT", "x"), ("QA_SERVICE_RUN_TIMEOUT", "1")):
        with pytest.raises(ConfigError):
            load_config(make_env(tmp_path, **{name: value}))


def test_the_command_must_exist(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(make_env(tmp_path, QA_SERVICE_CLI="no-such-command-qa"))


def test_the_module_refuses_to_start_without_a_token_and_exits_78(tmp_path):
    env = {"PATH": "/usr/bin:/bin", "QA_SERVICE_DATA_DIR": str(tmp_path)}
    done = subprocess.run([sys.executable, "-m", "qa_service"], env=dict(env, PYTHONPATH=str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src")), capture_output=True, text=True, timeout=30)
    assert done.returncode == 78 and "no token" in done.stderr and "not started" in done.stderr
