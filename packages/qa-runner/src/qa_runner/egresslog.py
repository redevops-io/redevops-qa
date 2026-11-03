# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""The audit file of a Robot lane that asked for the kernel layers: ``lanes/<lane>/egress-log.jsonl``. The first line says which layers were installed and what the self-test measured (or, for
a lane that was not started, why the layers are unavailable); every further line is one decision of the supervisor. The lane writes it (``lane_robot``), ``verify`` reads it; this module has
no dependency on either and none on the system calls, so the verifier that imports it opens no socket."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping, Optional, Tuple

LOG_NAME = "egress-log.jsonl"
LAYER_SECCOMP = "seccomp-user-notification"
LAYER_LANDLOCK = "landlock-tcp-connect"
ALL_LAYERS = (LAYER_SECCOMP, LAYER_LANDLOCK)
MAX_EVENTS = 5000
HEADER_KEYS = frozenset({"event", "layers", "arch", "kernel", "landlock_abi", "allowed", "selftest"})
UNAVAILABLE_KEYS = frozenset({"event", "reason", "message", "facts"})
EVENT_KEYS = frozenset({"seq", "layer", "syscall", "verdict", "reason", "family", "address", "port", "detail"})
VERDICTS = ("allow", "deny", "lost")
ARCHES = ("x86_64", "aarch64")


def _strict(line: bytes) -> Any:
    """One JSON value: no duplicate key, no float, no NaN or Infinity (the log holds integers and strings only)."""
    def pairs(items):
        keys = [k for k, _ in items]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate key")
        return dict(items)

    def refuse(_value):
        raise ValueError("not an integer or a string")
    return json.loads(line.decode("utf-8"), object_pairs_hook=pairs, parse_float=refuse, parse_constant=refuse)


def parse(data: bytes) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """The header, the events and what is wrong with the file (an empty list when nothing is). Strict: a line that is not one JSON object, a key that is not known, a type that is not the
    expected one or a sequence that is not 1, 2, 3, ... is a problem; nothing is repaired."""
    problems: List[str] = []
    rows: List[Dict[str, Any]] = []
    for i, line in enumerate(data.split(b"\n")[:-1] if data.endswith(b"\n") else data.split(b"\n")):
        try:
            row = _strict(line)
        except ValueError:                                  # includes a line that is not UTF-8
            problems.append(f"line {i + 1} is not one JSON object")
            continue
        if not isinstance(row, dict):
            problems.append(f"line {i + 1} is not one JSON object")
            continue
        rows.append(row)
    if not rows:
        return None, [], problems + ["the file is empty"]
    header, events = rows[0], rows[1:]
    if header.get("event") == "mechanism":
        if set(header) != HEADER_KEYS:
            problems.append("the first line does not have the fields of a mechanism record")
        elif (not isinstance(header["layers"], list) or not all(isinstance(x, str) for x in header["layers"]) or header["arch"] not in ARCHES or not isinstance(header["allowed"], list)
              or not all(isinstance(x, str) for x in header["allowed"]) or not isinstance(header["selftest"], dict)):
            problems.append("the first line has fields of the wrong type")
    elif header.get("event") == "unavailable":
        if set(header) != UNAVAILABLE_KEYS or not isinstance(header.get("reason"), str):
            problems.append("the first line does not have the fields of an unavailable record")
        elif events:
            problems.append("a lane that was not started has decisions")
    else:
        problems.append("the first line is neither a mechanism nor an unavailable record")
    if len(events) > MAX_EVENTS + 1:
        problems.append("more records than a run writes")
    for n, e in enumerate(events, 1):
        if not set(e) <= EVENT_KEYS or e.get("seq") != n or e.get("verdict") not in VERDICTS or not isinstance(e.get("syscall"), str) or not isinstance(e.get("reason"), str):
            problems.append(f"record {n} is not a decision record in sequence")
            break
        if "port" in e and (type(e["port"]) is not int or not 0 <= e["port"] < 65536):
            problems.append(f"record {n} has a port that is not a port")
            break
        if any(k in e and not isinstance(e[k], str) for k in ("layer", "family", "address", "detail")):
            problems.append(f"record {n} has a field of the wrong type")
            break
    return header, events, problems


def denied(events: List[Mapping[str, Any]]) -> int:
    """The refusals (and a lost supervisor) in a list of events."""
    return sum(1 for e in events if e.get("verdict") in ("deny", "lost"))
