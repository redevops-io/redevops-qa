# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The user an image runs as and its runtime configuration: entrypoint, command, working directory, variable names, volumes."""
from __future__ import annotations

from ._common import as_list, counts_only, text
from ._image import documents, identity, user_info

PROGRAM_ID = "image.user-and-runtime"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Image User, entrypoint, command, working directory, environment variable names, volumes"
SUPPORT = ("programs/_common.py", "programs/_image.py")
FRAMEWORK = ("image_store.py",)


def run(data):
    rows = []
    for d in documents(data):
        row = identity(d)
        row.update(user_info(d.get("user")))
        row.update({"config_present": d.get("config_present") is True,
                    "entrypoint": None if d.get("entrypoint") is None else [text(x) for x in as_list(d.get("entrypoint"))],
                    "cmd": None if d.get("cmd") is None else [text(x) for x in as_list(d.get("cmd"))],
                    "working_dir": text(d.get("working_dir")), "env_names": [text(x) for x in as_list(d.get("env_names"))],
                    "volumes": [text(x) for x in as_list(d.get("volumes"))], "stop_signal": text(d.get("stop_signal"))})
        rows.append(row)
    return {"images": rows,
            "counts": {"images": len(rows), "config_missing": sum(1 for r in rows if not r["config_present"]),
                       "user_unset": sum(1 for r in rows if r["config_present"] and r["user_unset"]),
                       "uid_zero": sum(1 for r in rows if r["config_present"] and r["uid_is_zero"] is True),
                       "uid_non_zero": sum(1 for r in rows if r["config_present"] and r["uid"] not in (None, 0)),
                       "user_by_name": sum(1 for r in rows if r["config_present"] and r["user_is_name"] and r["user"] != "root"),
                       "no_entrypoint_and_no_cmd": sum(1 for r in rows if r["config_present"] and not r["entrypoint"] and not r["cmd"])},
            "input_errors": []}


def run_counts(data):
    return counts_only(run(data))
