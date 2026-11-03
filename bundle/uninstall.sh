#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
# Remove an installation made by install.sh: the whole directory (virtual environment, browser directory, launcher), and nothing else.
#
#   ./uninstall.sh --prefix DIR
#
# The directory is removed only if it holds INSTALL.json written by install.sh and nothing but the entries that file names; any other content makes this script
# refuse, so a mistyped prefix cannot delete anything else. Evidence directories you chose elsewhere are not touched. System packages that
# `install-browser.sh --with-deps` installed with apt are not removed.
#
# Exit status: 0 removed; 2 usage; 5 the directory is not an installation of this bundle (nothing was removed).
set -eu
set -o pipefail
export LC_ALL=C

fail() { code="$1"; shift; echo "uninstall.sh: $*" >&2; exit "$code"; }

prefix=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) [ "$#" -ge 2 ] || fail 2 "--prefix needs a directory"; prefix="$2"; shift 2 ;;
    -h|--help) sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail 2 "unknown argument: $1 (see --help)" ;;
  esac
done
[ -n "$prefix" ] || fail 2 "--prefix DIR is required (see --help)"
case "$prefix" in /*) ;; *) fail 2 "the prefix must be an absolute path" ;; esac
case "$prefix" in /|//*) fail 2 "refusing to use $prefix" ;; esac
[ -d "$prefix" ] || fail 5 "$prefix is not a directory"
[ -f "$prefix/INSTALL.json" ] && [ ! -L "$prefix/INSTALL.json" ] || fail 5 "$prefix has no INSTALL.json: it is not an installation made by install.sh; nothing was removed"

for entry in "$prefix"/* "$prefix"/.[!.]* "$prefix"/..?*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  case "$(basename "$entry")" in
    venv|bin|browsers|INSTALL.json) ;;
    *) fail 5 "$prefix contains $(basename "$entry"), which install.sh did not create; nothing was removed" ;;
  esac
done

rm -rf -- "$prefix/venv" "$prefix/bin" "$prefix/browsers" "$prefix/INSTALL.json"
rmdir "$prefix" || fail 5 "$prefix could not be removed"
echo "removed $prefix"
