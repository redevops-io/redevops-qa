# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Shared pure helpers for image metadata programs."""
from __future__ import annotations

from ._common import as_list, as_map, text


def identity(doc):
    return {"digest": text(doc.get("digest")), "source": text(doc.get("source")), "kind": text(doc.get("kind")),
            "problems": sorted(text(p) for p in as_list(doc.get("problems")))}


def documents(data):
    return sorted(data.images, key=lambda d: (text(d.get("source")), text(d.get("digest"))))


def user_info(user):
    """Facts about an image ``User`` string: the user part is empty or root or numeric or a name that needs the image's passwd."""
    raw = text(user)
    name = raw.split(":", 1)[0]
    if name == "" or name == "root":
        uid = 0
    elif name.isdigit():
        uid = int(name)
    else:
        uid = None
    return {"user": raw, "user_unset": raw == "", "uid": uid, "uid_is_zero": (uid == 0) if uid is not None else None,
            "user_is_name": uid is None}


def port_rows(ports):
    rows = []
    for p in as_list(ports):
        s = text(p)
        num, _, proto = s.partition("/")
        rows.append({"port": int(num) if num.isdigit() else None, "protocol": proto or "tcp", "raw": s})
    return rows
