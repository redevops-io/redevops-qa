#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
# The browser step, separate from the install on purpose: it DOWNLOADS the three archives of the Playwright `chromium` install (Chrome for Testing, Chrome Headless Shell, FFmpeg)
# from the URLs the pinned Playwright uses, checks the sha256 and the size of each against browser.lock.json BEFORE unpacking it, unpacks them into <prefix>/browsers in the layout
# Playwright expects, and checks the unpacked tree (every directory and file: mode, size, sha256) against the same lock. Nothing is installed unless all of it matches; `redevops-qa doctor`
# makes the same tree check later. Not covered: the operating system libraries (--with-deps below), the Playwright CDN being reachable, anything outside <prefix>/browsers.
#
#   ./install-browser.sh --prefix DIR [--with-deps] [--mirror BASE]
#
# --with-deps  also install the operating system libraries Chromium needs (Debian and Ubuntu: `playwright install-deps chromium`, apt, through sudo unless you are root). These
#              packages are NOT covered by the pin: apt decides what is installed. Run it once per machine; uninstall.sh does not remove them. It runs after the archives were
#              verified and before anything is placed in <prefix>/browsers.
# --mirror     fetch <BASE>/<archive file name> instead of the URLs in the lock (BASE: an http(s):// or file:// URL, or an absolute directory). The bytes must still be the pinned ones.
#
# The archives are unpacked into <prefix>/browsers/.staging-<pid> and each install directory is renamed into place only after the whole tree matched the pin; a failure, or an INT, TERM or HUP
# (forwarded to the download), removes the staging directory and anything this run placed. A kill with SIGKILL, a power loss or the like cannot be caught: the staging directory stays and the
# next run removes a .staging-<pid> whose process is gone.
#
# Exit status: 0 installed (or already installed and identical to the pin); 2 usage (an unusable --mirror, for one); 4 the bundle has no browser.lock.json or it is not the installation's; 5 the
# prefix is not an installation made by install.sh; 6 the download, the check or the install failed (nothing was placed in <prefix>/browsers by this run; the message names the expected and
# the actual hash); 130, 143 or 129 stopped by INT, TERM or HUP.
set -eu
set -o pipefail
umask 022
export LC_ALL=C

here="$(cd "$(dirname "$0")" && pwd -P)"
fail() { code="$1"; shift; echo "install-browser.sh: $*" >&2; exit "$code"; }

prefix=""
deps=0
mirror=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) [ "$#" -ge 2 ] || fail 2 "--prefix needs a directory"; prefix="$2"; shift 2 ;;
    --with-deps) deps=1; shift ;;
    --mirror) [ "$#" -ge 2 ] || fail 2 "--mirror needs a base URL or an absolute directory"; mirror="$2"; shift 2 ;;
    -h|--help) sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail 2 "unknown argument: $1 (see --help)" ;;
  esac
done
[ -n "$prefix" ] || fail 2 "--prefix DIR is required (see --help)"
case "$prefix" in /*) ;; *) fail 2 "the prefix must be an absolute path" ;; esac
[ -f "$prefix/INSTALL.json" ] && [ -x "$prefix/venv/bin/python" ] || fail 5 "$prefix is not an installation made by install.sh"

# The pin: the bundle's browser.lock.json, and the copy the installation carries (installed from a hash-checked wheel); they must be the same file, or this script belongs to another bundle.
py="$prefix/venv/bin/python"
bundle_lock="$here/browser.lock.json"
installed_lock="$prefix/venv/share/redevops-qa/browser.lock.json"
[ -f "$bundle_lock" ] || fail 4 "browser.lock.json is missing from the bundle directory"
[ -f "$installed_lock" ] || fail 5 "the installation at $prefix does not carry browser.lock.json (it was made by a bundle without the browser pin)"
cmp -s "$bundle_lock" "$installed_lock" || fail 4 "the browser.lock.json of this bundle directory is not the one of the installation at $prefix: this script belongs to another bundle"
pin() { "$py" -I -m qa_runner.browser_pin "$@"; }

browsers="$prefix/browsers"
export PLAYWRIGHT_BROWSERS_PATH="$browsers"
created=0
if [ ! -e "$browsers" ]; then mkdir "$browsers" || fail 6 "cannot create $browsers"; created=1; fi
[ -d "$browsers" ] && [ ! -L "$browsers" ] || fail 5 "$browsers is not a directory"
staging="$browsers/.staging-$$"
fresh=""          # the install directories this run is going to place (the ones that are not there yet): removed again if the run does not end well
done_ok=0
child=0

# A child (the download, apt) runs in the background and is waited for, so that a signal sent to this script alone is acted on at once and reaches the child.
run_child() { "$@" & child=$!; local st=0; wait "$child" || st=$?; child=0; return "$st"; }
on_signal() {
  trap '' INT TERM HUP
  if [ "$child" -ne 0 ]; then kill -TERM "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi
  exit "$1"
}
cleanup() {
  rm -rf -- "$staging"
  if [ "$done_ok" -ne 1 ]; then
    for d in $fresh; do rm -rf -- "$browsers/$d"; done
    if [ "$created" -eq 1 ]; then rmdir "$browsers" 2>/dev/null || true; fi
  fi
}
trap cleanup EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
trap 'on_signal 129' HUP

# A staging directory of an earlier run that was killed without a chance to clean up (SIGKILL, power loss): removed when its process is gone. Only real directories of this exact name, inside
# the browsers directory; a link is left alone and never followed.
for stale in "$browsers"/.staging-*; do
  [ -d "$stale" ] && [ ! -L "$stale" ] || continue
  n="${stale##*/.staging-}"
  case "$n" in ''|*[!0-9]*) continue ;; esac
  if kill -0 "$n" 2>/dev/null || [ -d "/proc/$n" ]; then continue; fi          # its run is still going (kill -0 fails for another user's process; /proc does not)
  echo "removing the staging directory $stale left by an earlier run (process $n is gone)"
  rm -rf -- "$stale" 2>/dev/null || echo "warning: cannot remove $stale (for example it belongs to another user); leaving it and going on"
done

dirs_out="$(pin dirs --lock "$installed_lock")" || fail 6 "the lock could not be read"
for d in $dirs_out; do
  if [ ! -e "$browsers/$d" ] && [ ! -L "$browsers/$d" ]; then fresh="$fresh $d"; fi
done

echo "browser step: Chromium into $browsers, checked against the pin in browser.lock.json (the operating system libraries are not covered by it)"
mirror_args=()
[ -z "$mirror" ] || mirror_args=(--mirror "$mirror")
st=0
run_child "$py" -I -m qa_runner.browser_pin stage --lock "$installed_lock" --browsers "$browsers" --staging "$staging" ${mirror_args[@]+"${mirror_args[@]}"} || st=$?
[ "$st" -ne 2 ] || fail 2 "the --mirror argument cannot be used (see above); nothing was changed"
[ "$st" -eq 0 ] || fail 6 "the browser could not be downloaded and verified; nothing was installed"
if [ "$deps" -eq 1 ]; then
  echo "installing the operating system libraries Chromium needs (apt; not covered by the pin)"
  run_child "$py" -m playwright install-deps chromium || fail 6 "the operating system libraries could not be installed; nothing was placed in $browsers"
fi
out="$(pin commit --lock "$installed_lock" --browsers "$browsers" --staging "$staging")" || fail 6 "the verified browser could not be moved into place"
printf '%s\n' "$out"
# The same check `redevops-qa doctor` makes, on the installed tree.
pin verify --lock "$installed_lock" --browsers "$browsers" || fail 6 "the installed tree does not match the pin; what this run installed was removed"
done_ok=1
echo "browser directory: $browsers"
ls -1 "$browsers"
