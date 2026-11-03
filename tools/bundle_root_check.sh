#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
# The bundle as ROOT with HOME=/root, which neither the CI runner (/home/runner) nor tools/bundle_acceptance.sh (a temporary HOME) exercises:
#
#   1. install.sh refuses a prefix under /root (exit 2, the rule named, nothing created);
#   2. a prefix under /opt installs, `doctor` passes, and `demo` ends VERIFIED even though the evidence directory is under /root (only the installation and the temporary
#      directory are named on the Robot lane's command line, the evidence directory is not);
#      and, as the positive control, an installation under /opt with HOME, the evidence directory and TMPDIR all outside the refused places ends VERIFIED too;
#   3. a TMPDIR under /root (a path that IS on the Robot lane's command line) is named by `doctor` (exit 3, "adapter path policy", the path and the rule) and `demo` does not start
#      (exit 3, nothing created): an explicit configuration failure, not an INCONCLUSIVE run. The refused-path rule of the adapter kit is not touched.
#
#   tools/bundle_root_check.sh --current DIR [--python PATH]
#
# DIR holds <bundle name>.tar. Run it as root (the CI job uses sudo env HOME=/root PATH="$PATH"); it writes only under /opt/redevops-qa-root-check, /root/qa-root-check-* and a
# temporary directory, and removes them.
set -euo pipefail
export LC_ALL=C
current=""; py="python3.12"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --current) current="$2"; shift 2 ;;
    --python) py="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -d "$current" ] || { echo "usage: bundle_root_check.sh --current DIR [--python PATH]" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "run this as root (HOME=/root)" >&2; exit 2; }
export HOME=/root
step() { echo; echo "=== $*"; }
need() { if ! eval "$1"; then echo "ROOT CHECK FAILED: $2" >&2; exit 1; fi; }

name="$(basename "$(ls "$current"/*.tar | head -1)" .tar)"
work="$(mktemp -d)"
prefix=/opt/redevops-qa-root-check
evidence=/root/qa-root-check-evidence
tmpd=/root/qa-root-check-tmp
cleanup() { rm -rf "$work" "$evidence" "$tmpd" "${evidence}-2" /tmp/qa-root-check-home /tmp/qa-root-check-tmp /tmp/qa-root-check-evidence; [ ! -e "$prefix/INSTALL.json" ] || "$work/$name/uninstall.sh" --prefix "$prefix" >/dev/null 2>&1 || true; }
trap cleanup EXIT
tar xf "$current/$name.tar" -C "$work"
cd "$work/$name"

step "1. a prefix under /root is refused (exit 2), with the rule named, and nothing is created"
st=0; ./install.sh --prefix /root/redevops-qa --python "$py" > "$work/refused.out" 2>&1 || st=$?
cat "$work/refused.out"
need "[ $st -eq 2 ]" "install.sh exited $st for a prefix under /root, expected 2"
need 'grep -q "the directory /root" "$work/refused.out" && grep -q "PROHIBITED_PATH" "$work/refused.out" && grep -q "/opt/redevops-qa" "$work/refused.out"' "the refusal does not name the rule, the consequence and the remedy"
need '[ ! -e /root/redevops-qa ]' "/root/redevops-qa was created"

step "2. a prefix under /opt: install, browser step, doctor, demo with the evidence directory under /root"
./install.sh --prefix "$prefix" --python "$py"
./install-browser.sh --prefix "$prefix" --with-deps
"$prefix/bin/redevops-qa" doctor | tee "$work/doctor.out"
need 'grep -q "adapter path policy: the interpreter, the Robot guard script and the working directory of a run (TMPDIR) are paths the adapter path policy accepts" "$work/doctor.out" && grep -q "doctor: all required checks passed" "$work/doctor.out"' "doctor did not pass with the adapter path policy check"
"$prefix/bin/redevops-qa" demo --out "$evidence" | tee "$work/demo.out"
need 'grep -Eq "^run r0-[A-Za-z0-9._-]+: VERIFIED \(ALL_ASSERTIONS_VERIFIED\)" "$work/demo.out"' "the demo did not end VERIFIED"
need '[ "$(ls "$evidence" | wc -l)" -eq 1 ]' "no single evidence bundle under $evidence"

step "2b. the positive control: HOME, the evidence directory and TMPDIR all outside the refused places"
mkdir -p /tmp/qa-root-check-home /tmp/qa-root-check-tmp
HOME=/tmp/qa-root-check-home TMPDIR=/tmp/qa-root-check-tmp "$prefix/bin/redevops-qa" demo --out /tmp/qa-root-check-evidence | tee "$work/demo-control.out"
need 'grep -Eq "^run r0-[A-Za-z0-9._-]+: VERIFIED \(ALL_ASSERTIONS_VERIFIED\)" "$work/demo-control.out"' "the control demo (HOME, evidence and TMPDIR outside the refused places) did not end VERIFIED"

step "3. a TMPDIR under /root: doctor names the path and the rule (exit 3) and demo does not start"
mkdir -p "$tmpd"
st=0; TMPDIR="$tmpd" "$prefix/bin/redevops-qa" doctor > "$work/doctor2.out" 2>&1 || st=$?
cat "$work/doctor2.out"
need "[ $st -eq 3 ]" "doctor exited $st with TMPDIR under /root, expected 3"
need 'grep -q "adapter path policy: the temporary working directory of a run (from TMPDIR) is /root/qa-root-check-tmp/redevops-qa-<random> (the prefix /root is on the refused list)" "$work/doctor2.out"' "doctor did not name the path and the rule"
st=0; TMPDIR="$tmpd" "$prefix/bin/redevops-qa" demo --out "${evidence}-2" > "$work/demo2.out" 2>&1 || st=$?
cat "$work/demo2.out"
need "[ $st -eq 3 ]" "demo exited $st with TMPDIR under /root, expected 3 (refused before it starts)"
need 'grep -q "(the prefix /root is on the refused list)" "$work/demo2.out" && grep -q "Nothing was started" "$work/demo2.out"' "demo did not name the path and the rule and say that nothing was started"
need '[ ! -e "${evidence}-2" ]' "demo made an evidence directory although it did not start"

step "uninstall"
"$work/$name/uninstall.sh" --prefix "$prefix"
need '[ ! -e "$prefix" ]' "the installation directory is still there"
echo
echo "ROOT CHECK OK"
