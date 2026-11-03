#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
# The browser step, separate from the install on purpose: it DOWNLOADS Chromium from the Playwright download host into <prefix>/browsers.
# This is the one part of a setup that is not in the bundle and not hashed by it; BUNDLE.json records the build the pinned Playwright expects, and
# `redevops-qa doctor` reports the build that actually launches.
#
#   ./install-browser.sh --prefix DIR [--with-deps]
#
# --with-deps  also install the operating system libraries Chromium needs (Debian and Ubuntu: apt, through sudo unless you are root). Run it once per machine;
#              uninstall.sh does not remove them.
#
# Exit status: 0 installed; 2 usage; 5 the prefix is not an installation made by install.sh; 6 the download or the install failed.
set -eu
set -o pipefail
export LC_ALL=C

fail() { code="$1"; shift; echo "install-browser.sh: $*" >&2; exit "$code"; }

prefix=""
deps=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) [ "$#" -ge 2 ] || fail 2 "--prefix needs a directory"; prefix="$2"; shift 2 ;;
    --with-deps) deps="--with-deps"; shift ;;
    -h|--help) sed -n '3,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail 2 "unknown argument: $1 (see --help)" ;;
  esac
done
[ -n "$prefix" ] || fail 2 "--prefix DIR is required (see --help)"
case "$prefix" in /*) ;; *) fail 2 "the prefix must be an absolute path" ;; esac
[ -f "$prefix/INSTALL.json" ] && [ -x "$prefix/venv/bin/python" ] || fail 5 "$prefix is not an installation made by install.sh"

PLAYWRIGHT_BROWSERS_PATH="$prefix/browsers"
export PLAYWRIGHT_BROWSERS_PATH
echo "downloading Chromium into $PLAYWRIGHT_BROWSERS_PATH (not part of the bundle, not hashed by it)"
# shellcheck disable=SC2086
"$prefix/venv/bin/python" -m playwright install $deps chromium || fail 6 "the Chromium download or install failed"
echo "browser directory: $PLAYWRIGHT_BROWSERS_PATH"
ls -1 "$PLAYWRIGHT_BROWSERS_PATH"
