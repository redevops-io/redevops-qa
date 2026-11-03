#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Print the commands of one marked block of a README, exactly as written, so a CI job can run what the README tells a user to run.

    python tools/readme_block.py README.md NAME

A block is the fenced code block that follows the line ``<!-- bundle-commands: NAME -->``. Exit status 0 with the block on standard output; 1 when the marker is missing or
appears twice, or no fenced block follows it; 2 for a usage error. Standard library only.
"""
import re
import sys


def block(text: str, name: str) -> str:
    marker = f"<!-- bundle-commands: {name} -->"
    if text.count(marker) != 1:
        raise ValueError(f"the marker {marker!r} must appear exactly once (found {text.count(marker)})")
    after = text.split(marker, 1)[1]
    m = re.match(r"\s*```[A-Za-z]*\n(.*?)\n```", after, re.S)
    if not m:
        raise ValueError(f"no fenced code block follows {marker!r}")
    return m.group(1) + "\n"


def main(argv):
    if len(argv) != 3:
        print("usage: readme_block.py README.md NAME", file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding="utf-8") as fh:
            sys.stdout.write(block(fh.read(), argv[2]))
    except (OSError, ValueError) as exc:
        print(f"readme_block: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
