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
# Exit status: 0 installed; 2 usage, or a prefix under a path the adapter path policy refuses (for example /root); 3 the bundle is not for this Python or platform; 4 the bundle is damaged or does not match its checksums;
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
# A trailing slash or a trailing /. names the same directory: take them off before any test of the path, or `link/` and `link/.` would slip past the symbolic-link check.
while [ "${#prefix}" -gt 1 ]; do
  case "$prefix" in
    */) prefix="${prefix%/}" ;;
    */.) prefix="${prefix%/.}" ;;
    *) break ;;
  esac
done
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
"$python_bin" -I - "$here" "$prefix" <<'PY' || status=$?
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
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest) or not rel or rel.startswith("/") or ".." in rel.split("/") or rel in listed:
            print("install.sh: SHA256SUMS has a line this installer does not accept (malformed, empty, a path outside the bundle, or a path listed twice): %r" % line[:80], file=sys.stderr)
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

# The prefix must be somewhere the adapter path policy of this bundle accepts. The rule is read from the bundle itself (the constants of qa_adapter_kit/paths.py in the adapter kit wheel,
# parsed with ast, nothing executed) so that it cannot drift from what the runner enforces: a Robot lane whose command line names the installation (the interpreter and the guard script)
# under a refused path ends INCONCLUSIVE (PROHIBITED_PATH). The commonest case: an install under /root, as root.
import ast, glob, zipfile
kits = sorted(glob.glob(os.path.join(here, "wheelhouse", "redevops_qa_adapter_kit-*.whl")))
if kits:
    with zipfile.ZipFile(kits[0]) as zf:
        tree = ast.parse(zf.read("qa_adapter_kit/paths.py").decode("utf-8"))
    consts = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in ("DENIED_PREFIXES", "DENIED_COMPONENTS", "DENIED_NAMES"):
            value = node.value.args[0] if isinstance(node.value, ast.Call) else node.value
            consts[node.targets[0].id] = tuple(ast.literal_eval(value))
    if set(consts) != {"DENIED_PREFIXES", "DENIED_COMPONENTS", "DENIED_NAMES"}:
        print("install.sh: the adapter kit of this bundle does not define the path policy this installer reads; nothing was installed", file=sys.stderr)
        sys.exit(4)

    def refused(path):
        norm = os.path.normpath(path)
        for prefix in consts["DENIED_PREFIXES"]:
            if norm == prefix or norm.startswith(prefix + "/"):
                return "the directory " + prefix
        parts = [x for x in norm.split("/") if x]
        for part in parts:
            if part in consts["DENIED_COMPONENTS"]:
                return "a path component named " + part
        last = parts[-1] if parts else ""
        for name in consts["DENIED_NAMES"]:
            if last == name or last.startswith(name + "."):
                return "a file named " + name
        return ""
    given = os.path.normpath(sys.argv[2])
    for label, base in (("as given", given), ("with symbolic links resolved", os.path.realpath(given))):
        for path in (base, base + "/venv/bin/python", base + "/venv/lib/python%d.%d/site-packages/qa_runner/robot_guard.py" % sys.version_info[:2]):
            why = refused(path)
            if why:
                print("install.sh: the prefix (%s) puts the installation under %s, which the adapter path policy of this bundle refuses; the Robot lane would end INCONCLUSIVE "
                      "(PROHIBITED_PATH: its command line names the interpreter and the guard script of the installation). As root use a prefix outside /root, for example /opt/redevops-qa. "
                      "Nothing was changed." % (label, why), file=sys.stderr)
                sys.exit(2)
PY
[ "$status" -eq 0 ] || exit "$status"

[ ! -L "$prefix" ] || fail 5 "$prefix is a symbolic link: name the directory itself"
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

# HOME points into the prefix while the venv is made: a CPython from a toolcache has been seen creating a directory (.rustup) under whatever HOME it is started with when it makes a venv.
mkdir "$prefix/venv"
HOME="$prefix/venv" "$python_bin" -m venv "$prefix/venv" || fail 6 "the virtual environment could not be created (on Debian and Ubuntu: apt-get install python3-venv)"

# A clean environment for pip: no user configuration, no cache, no index.
if ! env -i PATH="$PATH" LC_ALL=C HOME="$prefix/venv" PIP_CONFIG_FILE=/dev/null PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 \
     "$prefix/venv/bin/python" -m pip install --no-index --find-links "$here/wheelhouse" --require-hashes --only-binary=:all: -r "$here/requirements.lock"; then
  fail 6 "pip refused the install (a wheel that does not match requirements.lock, a missing wheel, or a version that is not locked); nothing was installed"
fi

mkdir "$prefix/bin"
cat > "$prefix/bin/redevops-qa" <<EOF
#!/bin/sh
# Written by install.sh of the redevops-qa bundle: runs redevops-qa from this installation with the browser directory it uses.
# The installation does not read the caller's Python environment: a PYTHONPATH that holds another copy of a package (a stale checkout, for one) must not replace what was installed.
unset PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE PYTHONINSPECT PYTHONBREAKPOINT
PLAYWRIGHT_BROWSERS_PATH='$prefix/browsers'
export PLAYWRIGHT_BROWSERS_PATH
exec '$prefix/venv/bin/python' -E -s '$prefix/venv/bin/redevops-qa' "\$@"
EOF
chmod 755 "$prefix/bin/redevops-qa"

"$prefix/venv/bin/python" -I - "$here" "$prefix" <<'PY'
import hashlib, json, os, sys
here, prefix = sys.argv[1:3]
manifest = json.load(open(os.path.join(here, "BUNDLE.json"), encoding="utf-8"))
doc = {"schema": "redevops-qa/install", "schema_version": "1.0", "bundle": manifest["name"], "bundle_json_sha256": hashlib.sha256(open(os.path.join(here, "BUNDLE.json"), "rb").read()).hexdigest(),
       "python": "%d.%d.%d" % sys.version_info[:3], "prefix": os.path.realpath(prefix), "entries": ["venv", "bin", "browsers", "INSTALL.json"]}
with open(os.path.join(prefix, "INSTALL.json"), "x", encoding="utf-8") as fh:
    fh.write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
PY
done_ok=1
echo "installed $(basename "$here") into $prefix"
echo "next: the browser step (./install-browser.sh --prefix $prefix), then: $prefix/bin/redevops-qa doctor"
