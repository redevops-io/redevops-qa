#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
# Install the redevops-qa bundle into a NEW directory: a virtual environment with every package installed from the wheelhouse next to this script, with
#   pip install --no-index --find-links wheelhouse --require-hashes -r requirements.lock
# Nothing is downloaded, nothing outside the directory you name is written, and a failed install leaves nothing behind.
#
#   ./install.sh --prefix DIR [--python PATH]
#
# --prefix  an absolute path that does not exist or is an empty directory (to switch bundles, install the other one into a new directory; to roll back,
#           install the previous bundle into a new directory and delete the broken one with uninstall.sh)
# --python  the interpreter to build the virtual environment with (default: python3.12, then python3). It must be the Python minor and the platform
#           named in BUNDLE.json; anything else is refused before anything is created.
#
# Exit status: 0 installed; 2 usage; 3 the bundle is not for this Python or platform; 4 the bundle is damaged or does not match its checksums;
# 5 the prefix is not usable; 6 the environment or the install failed (and was removed).
set -eu
set -o pipefail
umask 022
export LC_ALL=C

here="$(cd "$(dirname "$0")" && pwd -P)"
prefix=""
python_bin=""

fail() { code="$1"; shift; echo "install.sh: $*" >&2; exit "$code"; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) [ "$#" -ge 2 ] || fail 2 "--prefix needs a directory"; prefix="$2"; shift 2 ;;
    --python) [ "$#" -ge 2 ] || fail 2 "--python needs a path"; python_bin="$2"; shift 2 ;;
    -h|--help) sed -n '3,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail 2 "unknown argument: $1 (see --help)" ;;
  esac
done
[ -n "$prefix" ] || fail 2 "--prefix DIR is required (see --help)"
case "$prefix" in /*) ;; *) fail 2 "the prefix must be an absolute path" ;; esac
case "$prefix" in *[!A-Za-z0-9._/+-]*) fail 2 "the prefix may contain only letters, digits and . _ / + - (it is written into a launcher script)" ;; esac
case "$prefix" in /|//*) fail 2 "refusing to use $prefix as a prefix" ;; esac

for f in BUNDLE.json requirements.lock SHA256SUMS wheelhouse; do
  [ -e "$here/$f" ] || fail 4 "$f is missing from the bundle directory"
done

if [ -z "$python_bin" ]; then
  for candidate in python3.12 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then python_bin="$(command -v "$candidate")"; break; fi
  done
fi
[ -n "$python_bin" ] && command -v "$python_bin" >/dev/null 2>&1 || fail 3 "no Python interpreter found (this bundle needs the Python named in BUNDLE.json)"

# Before anything is created: the interpreter and the platform are the ones the bundle was built for, and every file of the bundle is the one SHA256SUMS lists.
status=0
"$python_bin" -I - "$here" <<'PY' || status=$?
import hashlib, json, os, platform, sys
here = sys.argv[1]
manifest = json.load(open(os.path.join(here, "BUNDLE.json"), encoding="utf-8"))
target = manifest["target"]
have_python = "%d.%d" % sys.version_info[:2]
machine = platform.machine().lower().replace("amd64", "x86_64").replace("aarch64", "arm64")
have_platform = sys.platform.replace("darwin", "macos") + "-" + machine
if have_python != target["python"] or have_platform != target["platform"]:
    print("install.sh: this bundle is for Python %s on %s; this is Python %s on %s. Nothing was changed." % (target["python"], target["platform"], have_python, have_platform), file=sys.stderr)
    sys.exit(3)
listed = {}
with open(os.path.join(here, "SHA256SUMS"), encoding="utf-8") as fh:
    for line in fh:
        digest, _, rel = line.rstrip("\n").partition("  ")
        if len(digest) != 64 or not rel or rel.startswith("/") or ".." in rel.split("/"):
            print("install.sh: SHA256SUMS has a line this installer does not accept: %r" % line[:80], file=sys.stderr)
            sys.exit(4)
        listed[rel] = digest
present = set()
for dirpath, dirnames, filenames in os.walk(here):
    for name in filenames:
        rel = os.path.relpath(os.path.join(dirpath, name), here).replace(os.sep, "/")
        if rel != "SHA256SUMS":
            present.add(rel)
problems = ["not listed in SHA256SUMS: " + r for r in sorted(present - set(listed))] + ["listed but missing: " + r for r in sorted(set(listed) - present)]
for rel in sorted(present & set(listed)):
    h = hashlib.sha256()
    with open(os.path.join(here, rel), "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != listed[rel]:
        problems.append("checksum differs: " + rel)
if problems:
    print("install.sh: the bundle does not match its SHA256SUMS; nothing was installed:\n  " + "\n  ".join(problems[:20]), file=sys.stderr)
    sys.exit(4)
PY
[ "$status" -eq 0 ] || exit "$status"

created=0
if [ -e "$prefix" ]; then
  [ -d "$prefix" ] || fail 5 "$prefix exists and is not a directory"
  [ -z "$(ls -A "$prefix")" ] || fail 5 "$prefix is not empty. Install into a new directory (to roll back, install the previous bundle into a new directory)."
else
  mkdir -p "$prefix" || fail 5 "cannot create $prefix"
  created=1
fi

done_ok=0
cleanup() {
  if [ "$done_ok" -ne 1 ]; then
    rm -rf -- "$prefix/venv" "$prefix/bin" "$prefix/browsers" "$prefix/INSTALL.json"
    if [ "$created" -eq 1 ]; then rmdir "$prefix" 2>/dev/null || true; fi
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

"$python_bin" -m venv "$prefix/venv" || fail 6 "the virtual environment could not be created (on Debian and Ubuntu: apt-get install python3-venv)"

# A clean environment for pip: no user configuration, no cache, no index.
if ! env -i PATH="$PATH" LC_ALL=C HOME="$prefix/venv" PIP_CONFIG_FILE=/dev/null PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 \
     "$prefix/venv/bin/python" -m pip install --no-index --find-links "$here/wheelhouse" --require-hashes --only-binary=:all: -r "$here/requirements.lock"; then
  fail 6 "pip refused the install (a wheel that does not match requirements.lock, a missing wheel, or a version that is not locked); nothing was installed"
fi

mkdir "$prefix/bin"
cat > "$prefix/bin/redevops-qa" <<EOF
#!/bin/sh
# Written by install.sh of the redevops-qa bundle: runs redevops-qa from this installation with the browser directory it uses.
PLAYWRIGHT_BROWSERS_PATH='$prefix/browsers'
export PLAYWRIGHT_BROWSERS_PATH
exec '$prefix/venv/bin/redevops-qa' "\$@"
EOF
chmod 755 "$prefix/bin/redevops-qa"

"$prefix/venv/bin/python" -I - "$here" "$prefix" <<'PY'
import hashlib, json, os, sys
here, prefix = sys.argv[1:3]
manifest = json.load(open(os.path.join(here, "BUNDLE.json"), encoding="utf-8"))
doc = {"schema": "redevops-qa/install", "schema_version": "1.0", "bundle": manifest["name"], "bundle_json_sha256": hashlib.sha256(open(os.path.join(here, "BUNDLE.json"), "rb").read()).hexdigest(),
       "python": "%d.%d.%d" % sys.version_info[:3], "entries": ["venv", "bin", "browsers", "INSTALL.json"]}
with open(os.path.join(prefix, "INSTALL.json"), "x", encoding="utf-8") as fh:
    fh.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
PY
done_ok=1
echo "installed $(basename "$here") into $prefix"
echo "next: the browser step (./install-browser.sh --prefix $prefix), then: $prefix/bin/redevops-qa doctor"
