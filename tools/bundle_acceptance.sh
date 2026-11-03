#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
# The acceptance run of the bundle on a clean Linux x86_64 machine (the CI job runs it on ubuntu-24.04; it can run in an ubuntu:24.04 container too):
#
#   1. the commands of the bundle's README, taken from the README itself and run unchanged: unpack, install, the browser step, `doctor`, `demo`;
#   2. a second bundle (the "previous" one) installed into its own directory next to the first, `doctor` run with it, the first uninstalled: rollback;
#   3. the README's uninstall command, then a check that the installation directory is gone and nothing else was left under HOME except the evidence;
#   4. refusals, each on a fresh unpacked copy: a tampered wheel (sums unchanged: refused by the checksum step), a tampered wheel with SHA256SUMS rewritten
#      (refused by pip --require-hashes), a lock that names another version, a bundle for another Python minor and for another platform.
#
#   tools/bundle_acceptance.sh --current DIR --previous DIR
#
# DIR holds <bundle name>.tar and <bundle name>.tar.sha256 (what tools/build_bundle.py writes). Needs: bash, python3 (any, standard library only), sha256sum, tar,
# sudo or root for the browser step's --with-deps. Writes under $WORK (default: a new temporary directory) and HOME is set to a directory inside it.
set -euo pipefail
export LC_ALL=C

here="$(cd "$(dirname "$0")" && pwd -P)"
current=""; previous=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --current) current="$2"; shift 2 ;;
    --previous) previous="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -d "$current" ] && [ -d "$previous" ] || { echo "usage: bundle_acceptance.sh --current DIR --previous DIR" >&2; exit 2; }
current="$(cd "$current" && pwd -P)"; previous="$(cd "$previous" && pwd -P)"

WORK="${WORK:-$(mktemp -d)}"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd -P)"
export HOME="$WORK/home"
mkdir -p "$HOME" "$WORK/dl" "$WORK/blocks"
unset PLAYWRIGHT_BROWSERS_PATH PIP_INDEX_URL PIP_EXTRA_INDEX_URL PIP_FIND_LINKS
step() { echo; echo "=== $*"; }
need() { if ! eval "$1"; then echo "ACCEPTANCE FAILED: $2" >&2; exit 1; fi; }

name_of() { basename "$(ls "$1"/*.tar | head -1)" .tar; }
cur_name="$(name_of "$current")"; prev_name="$(name_of "$previous")"
echo "current:  $cur_name"; echo "previous: $prev_name"
cp "$current/$cur_name.tar" "$current/$cur_name.tar.sha256" "$WORK/dl/"
tar xOf "$WORK/dl/$cur_name.tar" "$cur_name/README.md" > "$WORK/blocks/README.md"
for b in unpack install use uninstall; do python3 "$here/readme_block.py" "$WORK/blocks/README.md" "$b" > "$WORK/blocks/$b.sh"; done

step "1. the README commands, unchanged: unpack, install, browser step, doctor, demo"
{ echo "set -euo pipefail"; cat "$WORK/blocks/unpack.sh" "$WORK/blocks/install.sh"; } > "$WORK/blocks/run-install.sh"
echo "--- run-install.sh"; cat "$WORK/blocks/run-install.sh"
( cd "$WORK/dl" && bash "$WORK/blocks/run-install.sh" )
need '[ -x "$HOME/redevops-qa/bin/redevops-qa" ]' "the launcher is missing"
{ echo "set -euo pipefail"; cat "$WORK/blocks/use.sh"; } > "$WORK/blocks/run-use.sh"
echo "--- run-use.sh"; cat "$WORK/blocks/run-use.sh"
( cd "$WORK/dl/$cur_name" && bash "$WORK/blocks/run-use.sh" ) | tee "$WORK/use.out"
need 'grep -q "doctor: all required checks passed" "$WORK/use.out"' "doctor did not report that all required checks passed"
need 'grep -Eq "^run r0-[A-Za-z0-9._-]+: VERIFIED \(ALL_ASSERTIONS_VERIFIED\)" "$WORK/use.out"' "the demo did not end VERIFIED"
need '[ "$(ls "$HOME/redevops-qa-evidence" | wc -l)" -eq 1 ]' "the demo wrote no single evidence bundle"

step "2. rollback: the previous bundle in its own directory, doctor with it, then the first one removed"
mkdir -p "$WORK/prev"          # the previous bundle may carry the same name as the current one (it differs in its label and its digest): never the same directory
cp "$previous/$prev_name.tar" "$WORK/prev/"
( cd "$WORK/prev" && tar xf "$prev_name.tar" && cd "$prev_name" && ./install.sh --prefix "$WORK/rollback" )
need '[ -x "$WORK/rollback/venv/bin/redevops-qa" ]' "the previous bundle did not install"
# the previous bundle has no browser of its own yet: give doctor the one the first installation downloaded (doctor changes nothing)
PLAYWRIGHT_BROWSERS_PATH="$HOME/redevops-qa/browsers" "$WORK/rollback/venv/bin/redevops-qa" doctor | tee "$WORK/rollback-doctor.out"
need 'grep -q "doctor: all required checks passed" "$WORK/rollback-doctor.out"' "doctor with the previous bundle did not pass"
need '! cmp -s "$WORK/rollback/INSTALL.json" "$HOME/redevops-qa/INSTALL.json"' "the two installations record the same bundle (the previous one is not another build)"

step "3. the README uninstall command, then: is the directory clean"
( cd "$WORK/dl/$cur_name" && bash -euo pipefail "$WORK/blocks/uninstall.sh" )
need '[ ! -e "$HOME/redevops-qa" ]' "the installation directory is still there after the uninstall"
need '[ -x "$WORK/rollback/venv/bin/redevops-qa" ] && "$WORK/rollback/venv/bin/redevops-qa" --version' "removing the first installation broke the other one"
# ACCEPTANCE_HOME_ALLOW: entries (space separated, as printed below) that something other than the bundle may create under HOME. Empty in CI. A container that emulates x86_64 on another
# processor writes ./.cache/rosetta there at once; a run there sets it to "./.cache" and says so.
left="$(cd "$HOME" && find . -mindepth 1 -maxdepth 1 | sort | tr '\n' ' ')"
echo "left under HOME: $left (allowed besides the evidence: '${ACCEPTANCE_HOME_ALLOW:-}')"
expected="./redevops-qa-evidence "
for extra in ${ACCEPTANCE_HOME_ALLOW:-}; do [ -e "$HOME/$extra" ] && expected="$(printf '%s\n%s' "$extra" "./redevops-qa-evidence" | sort | tr '\n' ' ')"; done
need '[ "$left" = "$expected" ]' "something besides the evidence directory is left under HOME: $left"
( cd "$WORK/prev/$prev_name" && ./uninstall.sh --prefix "$WORK/rollback" )
need '[ ! -e "$WORK/rollback" ]' "the second installation directory is still there"

step "4. refusals"
fresh() { rm -rf "$WORK/t"; mkdir "$WORK/t"; tar xf "$WORK/dl/$cur_name.tar" -C "$WORK/t"; echo "$WORK/t/$cur_name"; }
resum() { ( cd "$1" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | sort | xargs sha256sum > SHA256SUMS ); }
refused() { # refused EXPECTED_STATUS DIR [install args...]
  local want="$1" dir="$2"; shift 2; local st=0
  ( cd "$dir" && ./install.sh --prefix "$WORK/refused" "$@" ) > "$WORK/refusal.out" 2>&1 || st=$?
  cat "$WORK/refusal.out"
  need "[ $st -eq $want ]" "expected exit status $want from install.sh, got $st"
  need '[ ! -e "$WORK/refused" ]' "a refused install left $WORK/refused behind"
}
b="$(fresh)"; wheel="$(ls "$b"/wheelhouse/playwright-*.whl | head -1)"
printf 'x' >> "$wheel"
echo "--- tampered wheel, sums unchanged"; refused 4 "$b"; need 'grep -q "checksum differs" "$WORK/refusal.out"' "the checksum step did not name the tampered file"
resum "$b"
echo "--- tampered wheel, SHA256SUMS rewritten: pip --require-hashes"; refused 6 "$b"
need 'grep -q "THESE PACKAGES DO NOT MATCH THE HASHES" "$WORK/refusal.out"' "pip did not refuse the tampered wheel by hash"
b="$(fresh)"; sed -i 's/^redevops-qa-runner==[^ ]*/redevops-qa-runner==99.0/' "$b/requirements.lock"; resum "$b"
echo "--- a lock that names a version the wheelhouse does not hold"; refused 6 "$b"
b="$(fresh)"; python3 -I - "$b/BUNDLE.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p)); d["target"]["python"] = "3.11"; d["target"]["python_tag"] = "cp311"
json.dump(d, open(p, "w"), indent=2, sort_keys=True)
PY
resum "$b"
echo "--- a bundle for another Python minor (3.11)"; refused 3 "$b"; need 'grep -q "this bundle is for Python 3.11" "$WORK/refusal.out"' "the Python minor was not named"
b="$(fresh)"; python3 -I - "$b/BUNDLE.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p)); d["target"]["platform"] = "linux-arm64"
json.dump(d, open(p, "w"), indent=2, sort_keys=True)
PY
resum "$b"
echo "--- a bundle for another platform (linux-arm64)"; refused 3 "$b"
b="$(fresh)"; mkdir "$WORK/occupied"; touch "$WORK/occupied/file"
st=0; ( cd "$b" && ./install.sh --prefix "$WORK/occupied" ) > "$WORK/refusal.out" 2>&1 || st=$?; cat "$WORK/refusal.out"
need "[ $st -eq 5 ] && [ \"\$(ls \"$WORK/occupied\")\" = file ]" "a prefix that is not empty was not refused untouched"
rm -rf "$WORK/t"
echo
echo "ACCEPTANCE OK"
