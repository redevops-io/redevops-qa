#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
# The acceptance run of the bundle on a clean Linux x86_64 machine (the CI job runs it on ubuntu-24.04; it can run in an ubuntu:24.04 container too):
#
#   1. the commands of the bundle's README, taken from the README itself and run unchanged: unpack, install, the browser step, `doctor`, `demo`;
#   1b. the browser pin, negative cases on the installation of step 1: a browser that is not installed is reported as such; a changed file, a changed mode, an extra file and a missing
#       file each make `doctor` fail (naming the file) and make `demo` refuse to start the browser lane (exit status 3, no evidence directory), while a plan with only a Robot lane
#       still runs; restoring the file makes both pass again;
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

step "1b. the browser pin: the real install is exactly the pin, and a tampered browser fails doctor and the browser lane refuses to start"
need 'grep -q "^\[ OK \] browser build: Chromium " "$WORK/use.out"' "doctor did not report the browser build as matching the pin"
grep "browser build" "$WORK/use.out"
PY="$HOME/redevops-qa/venv/bin/python"
"$PY" -I -c 'import json; from qa_runner.golden import robot_plan; print(json.dumps(robot_plan()))' > "$WORK/robot-plan.json"
B="$HOME/redevops-qa/browsers"; QA="$HOME/redevops-qa/bin/redevops-qa"
victim="$B/chromium-*/chrome-linux64/ABOUT"; victim="$(ls $victim | head -1)"; exe="$(ls "$B"/chromium-*/chrome-linux64/chrome | head -1)"
cp -p "$victim" "$WORK/victim.orig"
has() { grep -Eq -- "$1" "$2"; }           # has PATTERN FILE
tamper_case() { # tamper_case NAME EXPECTED_CODE EXPECTED_PATH_FRAGMENT APPLY_COMMAND REVERT_COMMAND
  local name="$1" code="$2" frag="$3" st=0
  echo "--- tamper: $name"; eval "$4"
  "$QA" doctor > "$WORK/tamper-doctor.out" 2>&1 || st=$?; cat "$WORK/tamper-doctor.out"
  need "[ $st -eq 3 ]" "doctor must exit 3 for: $name (got $st)"
  need 'has "^\[FAIL\] browser build: .*not the pinned build" "$WORK/tamper-doctor.out"' "doctor did not fail the browser build for: $name"
  need 'has "$code" "$WORK/tamper-doctor.out" && has "$frag" "$WORK/tamper-doctor.out"' "doctor did not name the difference ($code, $frag) for: $name"
  need 'has "^\[FAIL\] chromium: not launched" "$WORK/tamper-doctor.out"' "doctor launched a browser that failed the pin check, for: $name"
  st=0; "$QA" demo --out "$WORK/tampered-evidence" > "$WORK/tamper-demo.out" 2>&1 || st=$?; cat "$WORK/tamper-demo.out"
  need "[ $st -eq 3 ]" "demo must refuse to start the browser lane with exit status 3 for: $name (got $st)"
  need 'has "BROWSER_PIN" "$WORK/tamper-demo.out"' "demo did not refuse with BROWSER_PIN for: $name"
  need '[ ! -e "$WORK/tampered-evidence" ]' "demo made an evidence directory although the browser lane was refused, for: $name"
  st=0; "$QA" run "$WORK/robot-plan.json" --out "$WORK/robot-evidence-${name// /_}" > "$WORK/tamper-robot.out" 2>&1 || st=$?; tail -3 "$WORK/tamper-robot.out"
  need '[ $st -eq 0 ] && has "VERIFIED" "$WORK/tamper-robot.out"' "a plan with only a Robot lane must still run with a tampered browser, for: $name (exit $st)"
  eval "$5"
  need '"$QA" doctor > "$WORK/restored-doctor.out" 2>&1 && has "^\[ OK \] browser build" "$WORK/restored-doctor.out"' "doctor did not pass again after restoring, for: $name"
}
tamper_case "one byte changed (same size)" CHANGED "chrome-linux64/ABOUT" 'python3 -I -c "import sys; f=open(sys.argv[1],\"r+b\"); b=f.read(1); f.seek(0); f.write(bytes([b[0]^1])); f.close()" "$victim"' 'cp -p "$WORK/victim.orig" "$victim"'
tamper_case "a byte appended (size changed)" SIZE "chrome-linux64/ABOUT" 'printf x >> "$victim"' 'cp -p "$WORK/victim.orig" "$victim"'
tamper_case "a changed file mode" MODE "chrome-linux64/chrome" 'chmod 0777 "$exe"' 'chmod 0755 "$exe"'
extra="$(dirname "$exe")/extra.so"
tamper_case "an extra file" EXTRA "chrome-linux64/extra.so" 'printf x > "$extra"' 'mv -f "$extra" "$WORK/extra.removed"'
tamper_case "a missing file" MISSING "chrome-linux64/ABOUT" 'mv -f "$victim" "$WORK/victim.moved"' 'mv -f "$WORK/victim.moved" "$victim"'
need '[ "$(cat "$victim")" = "$(cat "$WORK/victim.orig")" ]' "the tampered file was not restored"
rm -rf "$WORK"/robot-evidence-*

step "2. rollback: the previous bundle in its own directory, doctor with it, then the first one removed"
mkdir -p "$WORK/prev"          # the previous bundle may carry the same name as the current one (it differs in its label and its digest): never the same directory
cp "$previous/$prev_name.tar" "$WORK/prev/"
( cd "$WORK/prev" && tar xf "$prev_name.tar" && cd "$prev_name" && ./install.sh --prefix "$WORK/rollback" )
need '[ -x "$WORK/rollback/venv/bin/redevops-qa" ]' "the previous bundle did not install"
# the previous bundle has no browser of its own yet: give doctor the one the first installation downloaded (doctor changes nothing)
PLAYWRIGHT_BROWSERS_PATH="$HOME/redevops-qa/browsers" "$WORK/rollback/venv/bin/redevops-qa" doctor | tee "$WORK/rollback-doctor.out"
need 'grep -q "doctor: all required checks passed" "$WORK/rollback-doctor.out"' "doctor with the previous bundle did not pass"
need '! cmp -s "$WORK/rollback/INSTALL.json" "$HOME/redevops-qa/INSTALL.json"' "the two installations record the same bundle (the previous one is not another build)"
# an installation whose browser step has not been run: doctor says so
st=0; "$WORK/rollback/bin/redevops-qa" doctor > "$WORK/notinstalled.out" 2>&1 || st=$?; cat "$WORK/notinstalled.out"
need "[ $st -eq 3 ]" "doctor must fail for an installation without a browser (got $st)"
need 'grep -q "^\[FAIL\] browser build: not installed" "$WORK/notinstalled.out"' "doctor did not say that the browser is not installed"
need 'grep -q "install-browser.sh --prefix" "$WORK/notinstalled.out"' "doctor did not name the command that installs the browser"

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
