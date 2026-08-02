#!/bin/bash

set -euo pipefail
LC_ALL=C
export LC_ALL
umask 077

case ${BASH_SOURCE[0]} in */*) test_dir=${BASH_SOURCE[0]%/*} ;; *) test_dir=. ;; esac
builtin cd -P -- "$test_dir"
readonly TEST_DIR=$PWD
readonly REPO=${TEST_DIR%/tests}
readonly LAUNCHER="$REPO/nullsec-wolt-stage2b.sh"
readonly CORE="$REPO/lib/wolt-stage2b.py"
readonly FIXTURES="$TEST_DIR/fixtures/wolt-stage2b"
TMP=$(/usr/bin/mktemp -d "$FIXTURES/integration.XXXXXXXX")
[[ -n $TMP && $TMP == "$FIXTURES/integration."???????? && -d $TMP ]]
cleanup() {
    /bin/chmod -R u+rwX "$TMP" 2>/dev/null || true
    /bin/rm -rf -- "$TMP"
}
trap cleanup EXIT HUP INT TERM

pass=0
fail=0
ok() { pass=$((pass + 1)); builtin printf 'ok - %s\n' "$1"; }
not_ok() { fail=$((fail + 1)); builtin printf 'not ok - %s\n' "$1" >&2; }
check() { local label=$1; shift; if "$@"; then ok "$label"; else not_ok "$label"; fi; }
run_status() {
    local wanted=$1 label=$2; shift 2
    set +e
    "$@" >"$TMP/stdout" 2>"$TMP/stderr"
    local actual=$?
    set -e
    [[ $actual -eq $wanted ]] && ok "$label status" || not_ok "$label status ($actual != $wanted)"
}
exact_files() {
    [[ $(/usr/bin/find "$1" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | /usr/bin/sort) == "$2" ]]
}

check 'exact privileged shebang' test "$(/usr/bin/head -n 1 "$LAUNCHER")" = '#!/bin/bash -p'
check 'launcher executable mode' test -x "$LAUNCHER"
check 'launcher exact mode 0755' test "$(/usr/bin/stat -c %a "$LAUNCHER")" = 755
check 'launcher shell syntax' /bin/bash -n "$LAUNCHER"
check 'integration shell syntax' /bin/bash -n "$TEST_DIR/test-wolt-stage2b.sh"

set +e
(builtin cd "$REPO" && ./nullsec-wolt-stage2b.sh --help) >"$TMP/help-out" 2>"$TMP/help-err"
help_rc=$?
set -e
check 'executable shebang launch status' test "$help_rc" -eq 0
check 'help stderr empty' test ! -s "$TMP/help-err"
check 'help fixed usage' /usr/bin/grep -Fxq 'Usage: nullsec-wolt-stage2b.sh --source SOURCE --profile PROFILE --input ABSOLUTE_FILE --output ABSOLUTE_FILE' "$TMP/help-out"

set +e
/bin/bash -p "$LAUNCHER" --help >"$TMP/privileged-out" 2>"$TMP/privileged-err"
privileged_rc=$?
set -e
check 'equivalent privileged Bash status' test "$privileged_rc" -eq "$help_rc"
check 'equivalent privileged Bash stdout' /usr/bin/cmp -s "$TMP/privileged-out" "$TMP/help-out"
check 'equivalent privileged Bash stderr' /usr/bin/cmp -s "$TMP/privileged-err" "$TMP/help-err"

set +e
/bin/bash "$LAUNCHER" --help >"$TMP/ordinary-out" 2>"$TMP/ordinary-err"
ordinary_rc=$?
set -e
check 'ordinary Bash rejected status' test "$ordinary_rc" -eq 2
check 'ordinary Bash rejected stdout' test ! -s "$TMP/ordinary-out"
check 'ordinary Bash rejected token' /usr/bin/cmp -s "$TMP/ordinary-err" <(/usr/bin/printf 'STAGE2B_INTEGRITY_ERROR\n')

set +e
/bin/bash -p -c 'source "$1" --help' stage2b-source "$LAUNCHER" >"$TMP/sourcing-out" 2>"$TMP/sourcing-err"
sourcing_rc=$?
set -e
check 'sourcing rejected before Python core status' test "$sourcing_rc" -eq 2
check 'sourcing rejected before Python core stdout' test ! -s "$TMP/sourcing-out"
check 'sourcing rejected before Python core token' /usr/bin/cmp -s "$TMP/sourcing-err" <(/usr/bin/printf 'STAGE2B_INTEGRITY_ERROR\n')

check 'sanitized isolated Python invocation' /usr/bin/grep -Fq \
    'exec /usr/bin/env -i LC_ALL=C /usr/bin/python3 -I -S -B' "$LAUNCHER"
if ! /usr/bin/grep -E '^[[:space:]]*(source|\.)[[:space:]]|eval[[:space:]]|shell=True' "$LAUNCHER" "$CORE" >/dev/null; then
    ok 'no dynamic shell construct'
else
    not_ok 'no dynamic shell construct'
fi
if ! /usr/bin/grep -E '^[[:space:]]*(import|from)[[:space:]]+(socket|urllib|http|requests|subprocess|importlib|pickle|yaml|dns)([[:space:].]|$)' "$CORE" >/dev/null; then
    ok 'no forbidden production module'
else
    not_ok 'no forbidden production module'
fi
if ! /usr/bin/grep -E '(^|[ /])(curl|wget|nuclei|subfinder|assetfinder|amass|shodan|virustotal)($|[ /])' "$LAUNCHER" "$CORE" >/dev/null; then
    ok 'no provider or network executable path'
else
    not_ok 'no provider or network executable path'
fi
if ! /usr/bin/grep -E '(subprocess|os\.system|os\.popen|Popen|shell=True)' "$CORE" >/dev/null; then
    ok 'no Stage 1, Stage 2A, or nullsec execution path'
else
    not_ok 'no Stage 1, Stage 2A, or nullsec execution path'
fi

(builtin cd "$REPO" && /usr/bin/sha256sum -c /tmp/nullsec-wolt-stage2b-baseline.sha256) >"$TMP/baseline-before"
check 'protected baseline valid before integration' /usr/bin/grep -vq 'FAILED' "$TMP/baseline-before"

sentinels="$TMP/sentinels"
/bin/mkdir -m 700 "$sentinels"
sentinel_log="$TMP/sentinel.log"
: >"$sentinel_log"
for name in curl wget dig host nslookup getent nuclei subfinder assetfinder amass shodan virustotal nullsec.sh nullsec-wolt.sh nullsec-wolt-stage2a.sh; do
    /usr/bin/printf '#!/bin/bash\nprintf "%%s\\n" "%s" >>"%s"\nexit 125\n' "$name" "$sentinel_log" >"$sentinels/$name"
    /bin/chmod 700 "$sentinels/$name"
done
startup_log="$TMP/startup.log"
/usr/bin/printf 'printf "STARTUP_RAN\\n" >>"%s"\n' "$startup_log" >"$TMP/bash-env"

lines="$TMP/lines.txt"
/bin/cp "$FIXTURES/hostname-lines.txt" "$lines"
/bin/chmod 600 "$lines"
output="$TMP/success.json"
set +e
PATH="$sentinels" BASH_ENV="$TMP/bash-env" ENV="$TMP/bash-env" HOME="$TMP/secret-home" \
    SECRET_TOKEN='do-not-read' API_KEY='do-not-read' "$LAUNCHER" \
    --source subfinder --profile hostname-lines-v1 --input "$lines" --output "$output" \
    >"$TMP/run-out" 2>"$TMP/run-err"
run_rc=$?
set -e
check 'valid hostname conversion status' test "$run_rc" -eq 0
check 'valid hostname exact stdout' /usr/bin/cmp -s "$TMP/run-out" <(/usr/bin/printf 'STAGE2B_COMPLETE\n')
check 'valid hostname empty stderr' test ! -s "$TMP/run-err"
check 'published mode 0400' test "$(/usr/bin/stat -c %a "$output")" = 400
check 'network and provider sentinels untouched' test ! -s "$sentinel_log"
check 'shell startup sentinel untouched' test ! -e "$startup_log"

failure_input="$TMP/failure.json"
/bin/cp "$FIXTURES/failure-receipt.json" "$failure_input"
/bin/chmod 600 "$failure_input"
failure_output="$TMP/failure-envelope.json"
run_status 0 'valid retained failure conversion' "$LAUNCHER" --source shodan \
    --profile retained-provider-failure-v1 --input "$failure_input" --output "$failure_output"
check 'retained failure exact stdout' /usr/bin/cmp -s "$TMP/stdout" <(/usr/bin/printf 'STAGE2B_COMPLETE\n')
check 'retained failure empty stderr' test ! -s "$TMP/stderr"

empty="$TMP/empty"
: >"$empty"
empty_output="$TMP/empty-envelope.json"
run_status 0 'zero-result conversion' "$LAUNCHER" --source amass --profile hostname-lines-v1 \
    --input "$empty" --output "$empty_output"
check 'zero-result exact envelope' /usr/bin/grep -Fq '"record_count":0,"records":[]' "$empty_output"

repeat="$TMP/repeat.json"
run_status 0 'repeat conversion' "$LAUNCHER" --source subfinder --profile hostname-lines-v1 \
    --input "$lines" --output "$repeat"
check 'deterministic output' /usr/bin/cmp -s "$output" "$repeat"

existing="$TMP/existing.json"
/usr/bin/printf 'unchanged\n' >"$existing"
/bin/chmod 600 "$existing"
/bin/cp "$existing" "$TMP/existing-before"
run_status 6 'existing output rejection' "$LAUNCHER" --source amass --profile hostname-lines-v1 \
    --input "$lines" --output "$existing"
check 'existing output public token' /usr/bin/cmp -s "$TMP/stderr" <(/usr/bin/printf 'STAGE2B_PUBLICATION_ERROR\n')
check 'existing output unchanged' /usr/bin/cmp -s "$existing" "$TMP/existing-before"

malformed="$TMP/malformed"
/usr/bin/printf 'a.wolt.com\n\nb.wolt.com\n' >"$malformed"
run_status 3 'malformed input rejection' "$LAUNCHER" --source amass --profile hostname-lines-v1 \
    --input "$malformed" --output "$TMP/malformed-output"
check 'malformed exact stdout' test ! -s "$TMP/stdout"
check 'malformed public token' /usr/bin/cmp -s "$TMP/stderr" <(/usr/bin/printf 'STAGE2B_INPUT_ERROR\n')
check 'malformed output absent' test ! -e "$TMP/malformed-output"

run_status 64 'unknown live option rejection' "$LAUNCHER" --live
check 'usage public token' /usr/bin/cmp -s "$TMP/stderr" <(/usr/bin/printf 'STAGE2B_USAGE_ERROR\n')
for missing in source profile input output; do
    case $missing in
        source) set -- --source --profile --profile hostname-lines-v1 --input /a --output /b ;;
        profile) set -- --source amass --profile --input --input /a --output /b ;;
        input) set -- --source amass --profile hostname-lines-v1 --input --output --output /b ;;
        output) set -- --source amass --profile hostname-lines-v1 --input /a --output --source ;;
    esac
    run_status 64 "option-looking $missing value rejection" "$LAUNCHER" "$@"
    check "option-looking $missing value stdout" test ! -s "$TMP/stdout"
    check "option-looking $missing value token" /usr/bin/cmp -s "$TMP/stderr" <(/usr/bin/printf 'STAGE2B_USAGE_ERROR\n')
done
run_status 4 'unsupported native profile rejection' "$LAUNCHER" --source shodan --profile native-json-v1 \
    --input "$failure_input" --output "$TMP/native-output"
check 'schema public token' /usr/bin/cmp -s "$TMP/stderr" <(/usr/bin/printf 'STAGE2B_SCHEMA_ERROR\n')

check 'no provider or network sentinel touched' test ! -s "$sentinel_log"
check 'no Stage 1, Stage 2A, or nullsec sentinel touched' test ! -s "$sentinel_log"
if ! /usr/bin/find "$TMP" -type f -name '.stage2b-*' -print -quit | /usr/bin/grep -q .; then
    ok 'clean temporary-file behavior'
else
    not_ok 'clean temporary-file behavior'
fi
if ! /usr/bin/find "$REPO" -type d -name __pycache__ -print -quit | /usr/bin/grep -q . &&
   ! /usr/bin/find "$REPO" -type f -name '*.pyc' -print -quit | /usr/bin/grep -q .; then
    ok 'no bytecode artifacts'
else
    not_ok 'no bytecode artifacts'
fi
(builtin cd "$REPO" && /usr/bin/sha256sum -c /tmp/nullsec-wolt-stage2b-baseline.sha256) >"$TMP/baseline-after"
check 'protected baseline valid after integration' /usr/bin/grep -vq 'FAILED' "$TMP/baseline-after"

builtin printf 'SHELL_TEST_COUNTS pass=%d fail=%d total=%d\n' "$pass" "$fail" "$((pass + fail))"
[[ $fail -eq 0 ]]
