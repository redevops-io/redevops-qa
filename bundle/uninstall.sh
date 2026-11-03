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
# A trailing slash or a trailing /. names the same directory: take them off before any test of the path, or `link/` and `link/.` would slip past the symbolic-link check.
while [ "${#prefix}" -gt 1 ]; do
  case "$prefix" in
    */) prefix="${prefix%/}" ;;
    */.) prefix="${prefix%/.}" ;;
    *) break ;;
  esac
done
case "$prefix" in /*) ;; *) fail 2 "the prefix must be an absolute path" ;; esac
case "$prefix" in /|//*) fail 2 "refusing to use $prefix" ;; esac
[ ! -L "$prefix" ] || fail 5 "$prefix is a symbolic link: name the directory itself; nothing was removed"
[ -d "$prefix" ] || fail 5 "$prefix is not a directory"
[ -f "$prefix/INSTALL.json" ] && [ ! -L "$prefix/INSTALL.json" ] || fail 5 "$prefix has no INSTALL.json: it is not an installation made by install.sh; nothing was removed"
physical="$(cd "$prefix" && pwd -P)"
py=""
for candidate in python3.12 python3; do
  if command -v "$candidate" >/dev/null 2>&1; then py="$(command -v "$candidate")"; break; fi
done
[ -n "$py" ] || fail 5 "no Python interpreter found to read INSTALL.json; nothing was removed"
# INSTALL.json must be what install.sh wrote for THIS directory: the schema, the four entries, the physical path of the prefix, and a virtual environment inside.
"$py" -I - "$prefix/INSTALL.json" "$physical" <<'PY' || fail 5 "$prefix/INSTALL.json is not what install.sh writes for this directory; nothing was removed"
import json, re, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
ok = (isinstance(doc, dict) and doc.get("schema") == "redevops-qa/install" and doc.get("schema_version") == "1.0"
      and doc.get("entries") == ["venv", "bin", "browsers", "INSTALL.json"] and doc.get("prefix") == sys.argv[2]
      and isinstance(doc.get("bundle"), str) and doc["bundle"].startswith("redevops-qa-bundle-")
      and isinstance(doc.get("bundle_json_sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", doc["bundle_json_sha256"])
      and isinstance(doc.get("python"), str) and re.fullmatch(r"3\.[0-9]+\.[0-9]+", doc["python"]))
sys.exit(0 if ok else 1)
PY
[ -f "$prefix/venv/pyvenv.cfg" ] && [ -d "$prefix/bin" ] || fail 5 "$prefix has no virtual environment and launcher directory of install.sh; nothing was removed"

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
