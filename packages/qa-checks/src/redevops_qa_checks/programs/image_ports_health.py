# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Exposed ports and the declared health check of each image."""
from __future__ import annotations

from ._common import as_list, as_map, counts_only, text
from ._image import documents, identity, port_rows

PROGRAM_ID = "image.ports-and-health"
PROGRAM_VERSION = "1.0.0"
DESCRIPTION = "Image exposed ports and health check declaration"
SUPPORT = ("programs/_common.py", "programs/_image.py")
FRAMEWORK = ("image_store.py",)


def run(data):
    rows = []
    for d in documents(data):
        row = identity(d)
        hc = d.get("healthcheck")
        test = [text(x) for x in as_list(as_map(hc).get("test"))] if hc is not None else []
        row.update({"config_present": d.get("config_present") is True, "exposed_ports": port_rows(d.get("exposed_ports")),
                    "healthcheck_present": hc is not None, "healthcheck_test": test,
                    "healthcheck_disabled": test[:1] == ["NONE"],
                    "healthcheck_interval_ns": as_map(hc).get("interval") if hc is not None else None,
                    "healthcheck_timeout_ns": as_map(hc).get("timeout") if hc is not None else None,
                    "healthcheck_retries": as_map(hc).get("retries") if hc is not None else None,
                    "healthcheck_start_period_ns": as_map(hc).get("start_period") if hc is not None else None})
        rows.append(row)
    live = [r for r in rows if r["config_present"]]
    return {"images": rows,
            "counts": {"images": len(rows), "config_missing": len(rows) - len(live),
                       "with_exposed_ports": sum(1 for r in live if r["exposed_ports"]),
                       "exposed_ports_total": sum(len(r["exposed_ports"]) for r in live),
                       "with_healthcheck": sum(1 for r in live if r["healthcheck_present"] and not r["healthcheck_disabled"]),
                       "healthcheck_disabled": sum(1 for r in live if r["healthcheck_disabled"]),
                       "without_healthcheck": sum(1 for r in live if not r["healthcheck_present"])},
            "input_errors": []}


def run_counts(data):
    return counts_only(run(data))
