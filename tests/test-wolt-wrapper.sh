#!/bin/bash

set -uo pipefail
LC_ALL=C
export LC_ALL
umask 077

case ${BASH_SOURCE[0]} in
    */*) TEST_DIR=${BASH_SOURCE[0]%/*} ;;
    *) TEST_DIR=. ;;
esac

if ! builtin cd -P -- "$TEST_DIR"; then
    builtin printf '%s\n' "not ok - cannot resolve test directory" >&2
    exit 1
fi

TEST_DIR=$PWD
REPO_DIR=${TEST_DIR%/tests}
SOURCE_WRAPPER="$REPO_DIR/nullsec-wolt.sh"
SOURCE_CONFIG="$REPO_DIR/config"
readonly CLEAN_PATH=/usr/bin:/bin
readonly ENV_BIN=/usr/bin/env
readonly BASH_BIN=/bin/bash
readonly PYTHON_BIN=/usr/bin/python3

PASS=0
FAIL=0
SKIP=0
TEST_NUMBER=0

TMP_ROOT=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/nullsec-wolt-test.XXXXXXXX")
if [[ -z $TMP_ROOT || ! -d $TMP_ROOT ]]; then
    builtin printf '%s\n' "not ok - cannot create isolated test directory" >&2
    exit 1
fi

HARNESS_DIR="$TMP_ROOT/harness"
ISOLATED_REPO="$TMP_ROOT/isolated-repo"
ISOLATED_CONFIG="$ISOLATED_REPO/config"
ISOLATED_WRAPPER="$ISOLATED_REPO/nullsec-wolt.sh"
ISOLATED_NULLSEC="$ISOLATED_REPO/nullsec.sh"
SENTINEL_DIR="$HARNESS_DIR/network-sentinels"
SENTINEL_LOG="$HARNESS_DIR/network-sentinel.log"
NULLSEC_SENTINEL_LOG="$HARNESS_DIR/nullsec-sentinel.log"
HOME_DIR="$HARNESS_DIR/home"
HOSTILE_DIR="$HARNESS_DIR/hostile-working-directory"

/bin/mkdir -p "$ISOLATED_CONFIG" "$SENTINEL_DIR" "$HOME_DIR" "$HOSTILE_DIR"
/bin/cp -- "$SOURCE_WRAPPER" "$ISOLATED_WRAPPER"
/bin/cp -- "$SOURCE_CONFIG/wolt-approved-exact.txt" "$ISOLATED_CONFIG/"
/bin/cp -- "$SOURCE_CONFIG/wolt-excluded.txt" "$ISOLATED_CONFIG/"
/bin/cp -- "$SOURCE_CONFIG/wolt-mobile-assets.txt" "$ISOLATED_CONFIG/"
/bin/cp -- "$SOURCE_CONFIG/wolt-policy.json" "$ISOLATED_CONFIG/"

cleanup() {
    /bin/chmod -R u+rwX "$TMP_ROOT" 2>/dev/null
    /bin/rm -rf -- "$TMP_ROOT"
}
trap cleanup EXIT HUP INT TERM

record_pass() {
    TEST_NUMBER=$((TEST_NUMBER + 1))
    PASS=$((PASS + 1))
    builtin printf 'ok %d - %s\n' "$TEST_NUMBER" "$1"
}

record_fail() {
    TEST_NUMBER=$((TEST_NUMBER + 1))
    FAIL=$((FAIL + 1))
    builtin printf 'not ok %d - %s\n' "$TEST_NUMBER" "$1" >&2
}

assert_classification() {
    local expected_status=$1 expected_token=$2 input=$3 description=$4
    local output_file="$HARNESS_DIR/classification-output"
    local error_file="$HARNESS_DIR/classification-error"
    local output status line_count

    : >"$output_file"
    : >"$error_file"
    clean_invoke --classify "$input" >"$output_file" 2>"$error_file"
    status=$?
    IFS= builtin read -r output <"$output_file"
    line_count=$(/usr/bin/wc -l <"$output_file")

    if [[ $status -eq $expected_status &&
          $output == "$expected_token" &&
          $line_count -eq 1 ]]; then
        record_pass "$description"
    else
        record_fail "$description (status=$status token=$output lines=$line_count)"
    fi
}

assert_policy_failure() {
    local policy_directory=$1 expected_reason=$2 description=$3
    local output_file="$HARNESS_DIR/policy-output"
    local error_file="$HARNESS_DIR/policy-error"
    local output error status

    : >"$output_file"
    : >"$error_file"
    clean_invoke --test-policy-dir "$policy_directory" --classify wolt.com \
        >"$output_file" 2>"$error_file"
    status=$?
    IFS= builtin read -r output <"$output_file"
    IFS= builtin read -r error <"$error_file"

    if [[ $status -eq 2 &&
          $output == POLICY_ERROR &&
          $error == "policy validation failed: $expected_reason" ]]; then
        record_pass "$description"
    else
        record_fail "$description (status=$status token=$output reason=$error)"
    fi
}

make_policy_copy() {
    local destination=$1
    /bin/mkdir -p "$destination"
    /bin/cp -- "$SOURCE_CONFIG/wolt-approved-exact.txt" "$destination/"
    /bin/cp -- "$SOURCE_CONFIG/wolt-excluded.txt" "$destination/"
    /bin/cp -- "$SOURCE_CONFIG/wolt-mobile-assets.txt" "$destination/"
    /bin/cp -- "$SOURCE_CONFIG/wolt-policy.json" "$destination/"
}

snapshot_tree() {
    /usr/bin/find "$1" -mindepth 1 -printf '%P|%y|%m|%s|%T@|%l\n' |
        /usr/bin/sort >"$2"
}

clean_invoke() {
    "$ENV_BIN" -i \
        PATH="$SENTINEL_DIR:$CLEAN_PATH" \
        HOME="$HOME_DIR" \
        LC_ALL=C \
        NULLSEC_WOLT_SENTINEL_LOG="$SENTINEL_LOG" \
        NULLSEC_WOLT_NULLSEC_LOG="$NULLSEC_SENTINEL_LOG" \
        "$BASH_BIN" "$ISOLATED_WRAPPER" "$@"
}

if "$BASH_BIN" -n "$SOURCE_WRAPPER" &&
   "$BASH_BIN" -n "$TEST_DIR/test-wolt-wrapper.sh"; then
    record_pass "Bash syntax validation succeeds"
else
    record_fail "Bash syntax validation succeeds"
fi

NETWORK_COMMANDS=(
    curl wget dig host nslookup getent
    subfinder amass amass-v4 assetfinder puredns dnsx
    httpx httpx-toolkit katana hakrawler gau waybackurls gospider cariddi
    ffuf nuclei naabu nmap arjun dalfox sqlmap gowitness
    cloud_enum s3scanner aws gcloud az nc netcat socat openssl
    python python3 perl ruby php node
)

builtin printf '%s\n' \
    '#!/bin/bash' \
    'builtin printf "%s\n" "${0##*/}" >>"${NULLSEC_WOLT_SENTINEL_LOG:?}"' \
    'exit 125' >"$SENTINEL_DIR/network-sentinel"
/bin/chmod 700 "$SENTINEL_DIR/network-sentinel"
for command_name in "${NETWORK_COMMANDS[@]}"; do
    /bin/ln -s network-sentinel "$SENTINEL_DIR/$command_name"
done

builtin printf '%s\n' \
    '#!/bin/bash' \
    'builtin printf "%s\n" invoked >>"${NULLSEC_WOLT_NULLSEC_LOG:?}"' \
    'exit 126' >"$ISOLATED_NULLSEC"
/bin/chmod 700 "$ISOLATED_NULLSEC"

STATIC_CODE="$HARNESS_DIR/wrapper-code-only"
/usr/bin/awk '/^[[:space:]]*#/ { next } { print }' \
    "$SOURCE_WRAPPER" >"$STATIC_CODE"

if ! /usr/bin/grep -Eq \
    '(^|[[:space:];|&])(source|exec)[[:space:]]|[[:space:]]\.[[:space:]].*nullsec|/dev/(tcp|udp)|nullsec\.sh[[:space:]]' \
    "$STATIC_CODE"; then
    record_pass "no source, exec, NullSec invocation, or Bash network device"
else
    record_fail "no source, exec, NullSec invocation, or Bash network device"
fi

if ! /usr/bin/grep -Eq \
    '(^|[[:space:];|&])(curl|wget|dig|host|nslookup|getent|subfinder|amass|assetfinder|puredns|dnsx|httpx|katana|hakrawler|gau|waybackurls|ffuf|nuclei|naabu|nmap|arjun|dalfox|sqlmap|gowitness|nc|netcat|socat|openssl)[[:space:]]' \
    "$STATIC_CODE"; then
    record_pass "no direct network-capable tool execution"
else
    record_fail "no direct network-capable tool execution"
fi

if ! /usr/bin/grep -Eq '(^|[[:space:]])(--run|--scan)([[:space:]]|$)' \
    "$SOURCE_WRAPPER"; then
    record_pass "no run or scan option"
else
    record_fail "no run or scan option"
fi

for asset in \
    wolt.com restaurant-api.wolt.com ops.wolt.com merchant.wolt.com \
    drive.wolt.com corporate.wolt.com authentication.wolt.com
do
    assert_classification 0 APPROVED_EXACT "$asset" "approved exact: $asset"
done
assert_classification 0 APPROVED_EXACT WOLT.COM "case-insensitive exact approval"
assert_classification 0 APPROVED_EXACT OPS.WOLT.COM. \
    "case and terminal-dot exact approval"

for asset in api.wolt.com a.b.wolt.com new-service.wolt.com \
    press2.wolt.com restaurant-api.dev.wolt.com
do
    assert_classification 10 PENDING_WILDCARD_REVIEW "$asset" \
        "wildcard candidate remains pending: $asset"
done

for asset in wolt.atlassian.net press.wolt.com links.wolt.com \
    gettest.wolt.com blog.wolt.com
do
    assert_classification 11 EXCLUDED "$asset" "explicit exclusion: $asset"
done
for asset in WOLT.ATLASSIAN.NET. PRESS.WOLT.COM. LINKS.WOLT.COM. \
    GETTEST.WOLT.COM. BLOG.WOLT.COM.
do
    assert_classification 11 EXCLUDED "$asset" \
        "canonicalized exclusion: $asset"
done
assert_classification 10 PENDING_WILDCARD_REVIEW x.press.wolt.com \
    "exact exclusion is not an implicit subtree exclusion"
assert_classification 12 NON_WOLT press.wolt.com.example \
    "suffix confusion rejected"
assert_classification 10 PENDING_WILDCARD_REVIEW evilpress.wolt.com \
    "exclusion respects label boundary"

for asset in com.wolt.courierapp com.wolt.android 943905271 1477299281
do
    assert_classification 13 MOBILE_ASSET "$asset" "mobile asset: $asset"
done
assert_classification 13 MOBILE_ASSET COM.WOLT.ANDROID \
    "mobile classification is case-insensitive"
assert_classification 13 MOBILE_ASSET com.wolt.future_app \
    "future Wolt package form blocked"
assert_classification 14 MALFORMED 123456789 \
    "unknown numeric App Store-like ID malformed"

for asset in https://wolt.com http://ops.wolt.com ftp://wolt.com \
    //wolt.com https://user@wolt.com 'https://wolt.com:443/path?q=x#f'
do
    assert_classification 14 MALFORMED "$asset" "URL or URI rejected"
done

for asset in 127.0.0.1 001.002.003.004 999.999.999.999 \
    1.2 1.2.3 1.2.3.4 1.2.3.4.5 1..2 .1.2.3 1.2.3. \
    192.0.2.0/24 2001:db8::1 '[2001:db8::1]' \
    '[2001:db8::1]:443' wolt.com:443 ops.wolt.com:80
do
    assert_classification 14 MALFORMED "$asset" \
        "address, numeric dotted form, CIDR, or port rejected: $asset"
done

for asset in wolt.com/ wolt.com/login 'wolt.com?x=1' \
    'wolt.com#fragment' user@wolt.com user:pass@wolt.com \
    'wolt.com\path' '*.wolt.com' 'api.*.wolt.com' \
    'wolt.com;id' 'wolt.com&&id' 'wolt.com|id' 'wolt.com`id`' \
    'wolt.com$(id)' 'wolt.com${PATH}' 'wolt.com>file' \
    'wolt.com<input' 'wolt.com(foo)' 'wolt.com{foo}' \
    'wolt.com[foo]' '"wolt.com"' "'wolt.com'" '-wolt.com'
do
    assert_classification 14 MALFORMED "$asset" \
        "component or shell syntax rejected"
done

assert_classification 14 MALFORMED "" "empty input rejected"
assert_classification 14 MALFORMED " " "space input rejected"
assert_classification 14 MALFORMED " wolt.com" "leading space rejected"
assert_classification 14 MALFORMED "wolt.com " "trailing space rejected"
assert_classification 14 MALFORMED "wolt .com" "embedded space rejected"
assert_classification 14 MALFORMED $'wolt\t.com' "tab rejected without reflection"
assert_classification 14 MALFORMED $'wolt\r.com' "CR rejected without reflection"
assert_classification 14 MALFORMED $'wolt\n.com' "LF rejected without reflection"
assert_classification 14 MALFORMED $'wolt\e.com' "escape rejected without reflection"
assert_classification 14 MALFORMED $'wolt\x7f.com' "DEL rejected without reflection"
assert_classification 14 MALFORMED $'wölt.com' "Unicode rejected"
assert_classification 14 MALFORMED xn--wlt-5qa.com "punycode rejected"
assert_classification 14 MALFORMED xn--wlt-5qa.wolt.com \
    "Wolt punycode rejected"
assert_classification 14 MALFORMED api.xn--wlt-5qa.wolt.com \
    "nested punycode rejected"

label63=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
label64=${label63}a
assert_classification 14 MALFORMED localhost "single-label rejected"
assert_classification 14 MALFORMED a..wolt.com "empty label rejected"
assert_classification 14 MALFORMED a-.wolt.com "trailing hyphen rejected"
assert_classification 14 MALFORMED a_b.wolt.com "underscore rejected"
assert_classification 10 PENDING_WILDCARD_REVIEW "$label63.wolt.com" \
    "63-byte label accepted"
assert_classification 14 MALFORMED "$label64.wolt.com" \
    "64-byte label rejected"
assert_classification 14 MALFORMED wolt.com.. "multiple terminal dots rejected"

hostile_output="$HARNESS_DIR/hostile-output"
(
    builtin cd -- "$HOSTILE_DIR" || exit 99
    clean_invoke --classify wolt.com
) >"$hostile_output" 2>/dev/null
hostile_status=$?
IFS= builtin read -r hostile_token <"$hostile_output"
if [[ $hostile_status -eq 0 && $hostile_token == APPROVED_EXACT ]]; then
    record_pass "hostile working directory cannot redirect policy"
else
    record_fail "hostile working directory cannot redirect policy"
fi

BASH_ENV_ATTACK="$HARNESS_DIR/bash-env-attack"
STARTUP_ATTACK_LOG="$HARNESS_DIR/startup-attack.log"
builtin printf '%s\n' \
    'builtin printf "%s\n" BASH_ENV_RAN >>"${STARTUP_ATTACK_LOG:?}"' \
    'curl https://invalid.example/' >"$BASH_ENV_ATTACK"
curl() {
    builtin printf '%s\n' EXPORTED_FUNCTION_RAN >>"${STARTUP_ATTACK_LOG:?}"
    return 125
}
export BASH_ENV="$BASH_ENV_ATTACK" STARTUP_ATTACK_LOG
export -f curl
startup_output="$HARNESS_DIR/startup-output"
clean_invoke --classify wolt.com >"$startup_output" 2>/dev/null
startup_status=$?
unset BASH_ENV
unset -f curl
IFS= builtin read -r startup_token <"$startup_output"
if [[ $startup_status -eq 0 && $startup_token == APPROVED_EXACT &&
      ! -e $STARTUP_ATTACK_LOG ]]; then
    record_pass "sanitized launcher strips BASH_ENV and exported functions"
else
    record_fail "sanitized launcher strips BASH_ENV and exported functions"
fi
unset STARTUP_ATTACK_LOG

classification_file="$HARNESS_DIR/classification-file"
builtin printf '%s\n' wolt.com api.wolt.com press.wolt.com >"$classification_file"
file_output="$HARNESS_DIR/file-output"
clean_invoke --classify-file "$classification_file" >"$file_output" 2>/dev/null
file_status=$?
if [[ $file_status -eq 20 &&
      $(/usr/bin/sed -n '1p' "$file_output") == APPROVED_EXACT &&
      $(/usr/bin/sed -n '2p' "$file_output") == PENDING_WILDCARD_REVIEW &&
      $(/usr/bin/sed -n '3p' "$file_output") == EXCLUDED ]]; then
    record_pass "classification file emits fixed tokens"
else
    record_fail "classification file emits fixed tokens"
fi

no_final_lf="$HARNESS_DIR/no-final-lf-input"
builtin printf '%s' wolt.com >"$no_final_lf"
clean_invoke --classify-file "$no_final_lf" >"$file_output" 2>/dev/null
no_lf_status=$?
IFS= builtin read -r no_lf_token <"$file_output"
if [[ $no_lf_status -eq 0 && $no_lf_token == APPROVED_EXACT ]]; then
    record_pass "input final line without LF accepted"
else
    record_fail "input final line without LF accepted"
fi

empty_input="$HARNESS_DIR/empty-input"
: >"$empty_input"
clean_invoke --classify-file "$empty_input" >"$file_output" 2>/dev/null
empty_status=$?
IFS= builtin read -r empty_token <"$file_output"
if [[ $empty_status -eq 3 && $empty_token == INPUT_ERROR ]]; then
    record_pass "empty input file fails closed"
else
    record_fail "empty input file fails closed"
fi

nul_input="$HARNESS_DIR/nul-input"
"$PYTHON_BIN" -I -S -c \
    'open(__import__("sys").argv[1],"wb").write(b"wo\x00lt.com\n")' "$nul_input"
clean_invoke --classify-file "$nul_input" >"$file_output" 2>/dev/null
nul_status=$?
IFS= builtin read -r nul_token <"$file_output"
if [[ $nul_status -eq 3 && $nul_token == INPUT_ERROR ]]; then
    record_pass "NUL input file rejected before Bash parsing"
else
    record_fail "NUL input file rejected before Bash parsing"
fi

input_symlink="$HARNESS_DIR/input-symlink"
/bin/ln -s "$classification_file" "$input_symlink"
clean_invoke --classify-file "$input_symlink" >"$file_output" 2>/dev/null
input_link_status=$?
IFS= builtin read -r input_link_token <"$file_output"
if [[ $input_link_status -eq 3 && $input_link_token == INPUT_ERROR ]]; then
    record_pass "symlinked input file rejected"
else
    record_fail "symlinked input file rejected"
fi

missing_policy="$HARNESS_DIR/policy-missing"
make_policy_copy "$missing_policy"
/bin/rm "$missing_policy/wolt-approved-exact.txt"
assert_policy_failure "$missing_policy" approved_missing_or_nonregular \
    "missing policy fails closed"

empty_policy="$HARNESS_DIR/policy-empty"
make_policy_copy "$empty_policy"
: >"$empty_policy/wolt-approved-exact.txt"
assert_policy_failure "$empty_policy" approved_raw_bytes_invalid \
    "empty policy fails closed"

unreadable_policy="$HARNESS_DIR/policy-unreadable"
make_policy_copy "$unreadable_policy"
/bin/chmod 000 "$unreadable_policy/wolt-approved-exact.txt"
assert_policy_failure "$unreadable_policy" approved_raw_bytes_invalid \
    "unreadable policy fails closed"
/bin/chmod 600 "$unreadable_policy/wolt-approved-exact.txt"

symlink_policy="$HARNESS_DIR/policy-symlink"
make_policy_copy "$symlink_policy"
/bin/mv "$symlink_policy/wolt-approved-exact.txt" "$symlink_policy/approved-real"
/bin/ln -s approved-real "$symlink_policy/wolt-approved-exact.txt"
assert_policy_failure "$symlink_policy" approved_symlink \
    "symlinked policy fails closed"

duplicate_policy="$HARNESS_DIR/policy-duplicate"
make_policy_copy "$duplicate_policy"
builtin printf '%s\n' wolt.com >>"$duplicate_policy/wolt-approved-exact.txt"
assert_policy_failure "$duplicate_policy" approved_duplicate \
    "duplicate policy fails closed"

malformed_policy="$HARNESS_DIR/policy-malformed"
make_policy_copy "$malformed_policy"
/usr/bin/sed -i 's#authentication.wolt.com#bad/path.wolt.com#' \
    "$malformed_policy/wolt-approved-exact.txt"
assert_policy_failure "$malformed_policy" approved_component_character \
    "malformed policy fails closed"

unexpected_policy="$HARNESS_DIR/policy-unexpected"
make_policy_copy "$unexpected_policy"
/usr/bin/sed -i 's/authentication.wolt.com/unexpected.wolt.com/' \
    "$unexpected_policy/wolt-approved-exact.txt"
assert_policy_failure "$unexpected_policy" approved_missing_required \
    "same-count policy drift fails closed"

conflict_policy="$HARNESS_DIR/policy-conflict"
make_policy_copy "$conflict_policy"
/usr/bin/sed -i 's/authentication.wolt.com/press.wolt.com/' \
    "$conflict_policy/wolt-approved-exact.txt"
assert_policy_failure "$conflict_policy" approved_excluded_conflict \
    "approved/excluded conflict fails closed first"

nul_policy="$HARNESS_DIR/policy-nul"
make_policy_copy "$nul_policy"
"$PYTHON_BIN" -I -S -c \
    'p=__import__("sys").argv[1];d=open(p,"rb").read();open(p,"wb").write(d+b"x\x00\n")' \
    "$nul_policy/wolt-approved-exact.txt"
assert_policy_failure "$nul_policy" approved_raw_bytes_invalid \
    "NUL policy rejected before Bash parsing"

unicode_policy="$HARNESS_DIR/policy-unicode"
make_policy_copy "$unicode_policy"
"$PYTHON_BIN" -I -S -c \
    'p=__import__("sys").argv[1];d=open(p,"rb").read();open(p,"wb").write(d+"wölt.com\n".encode())' \
    "$unicode_policy/wolt-approved-exact.txt"
assert_policy_failure "$unicode_policy" approved_raw_bytes_invalid \
    "Unicode policy rejected before Bash parsing"

no_lf_policy="$HARNESS_DIR/policy-no-lf"
make_policy_copy "$no_lf_policy"
"$PYTHON_BIN" -I -S -c \
    'p=__import__("sys").argv[1];d=open(p,"rb").read();open(p,"wb").write(d.rstrip(b"\n"))' \
    "$no_lf_policy/wolt-approved-exact.txt"
no_lf_policy_output="$HARNESS_DIR/no-lf-policy-output"
clean_invoke --test-policy-dir "$no_lf_policy" --classify wolt.com \
    >"$no_lf_policy_output" 2>/dev/null
no_lf_policy_status=$?
IFS= builtin read -r no_lf_policy_token <"$no_lf_policy_output"
if [[ $no_lf_policy_status -eq 0 &&
      $no_lf_policy_token == APPROVED_EXACT ]]; then
    record_pass "policy final line without LF accepted"
else
    record_fail "policy final line without LF accepted"
fi

malformed_json="$HARNESS_DIR/json-malformed"
make_policy_copy "$malformed_json"
builtin printf '%s\n' '{' >"$malformed_json/wolt-policy.json"
assert_policy_failure "$malformed_json" json_policy_semantic_mismatch \
    "malformed JSON fails closed"

duplicate_json="$HARNESS_DIR/json-duplicate"
make_policy_copy "$duplicate_json"
"$PYTHON_BIN" -I -S -c \
    'p=__import__("sys").argv[1];d=open(p).read();open(p,"w").write(d.replace("{","{\"schema_version\":1,",1))' \
    "$duplicate_json/wolt-policy.json"
assert_policy_failure "$duplicate_json" json_policy_semantic_mismatch \
    "duplicate JSON key fails closed"

json_drift="$HARNESS_DIR/json-drift"
make_policy_copy "$json_drift"
"$PYTHON_BIN" -I -S -c \
    'import json,sys;p=sys.argv[1];d=json.load(open(p));d["stage"]=2;open(p,"w").write(json.dumps(d))' \
    "$json_drift/wolt-policy.json"
assert_policy_failure "$json_drift" json_policy_semantic_mismatch \
    "semantic JSON drift fails closed"

policy_dir_link="$HARNESS_DIR/policy-dir-link"
/bin/ln -s "$SOURCE_CONFIG" "$policy_dir_link"
assert_policy_failure "$policy_dir_link" test_policy_directory_symlink \
    "symlinked test policy directory rejected"

wrapper_link="$HARNESS_DIR/wrapper-link"
/bin/ln -s "$ISOLATED_WRAPPER" "$wrapper_link"
wrapper_link_output="$HARNESS_DIR/wrapper-link-output"
"$ENV_BIN" -i PATH="$SENTINEL_DIR:$CLEAN_PATH" HOME="$HOME_DIR" LC_ALL=C \
    "$BASH_BIN" "$wrapper_link" --classify wolt.com \
    >"$wrapper_link_output" 2>/dev/null
wrapper_link_status=$?
IFS= builtin read -r wrapper_link_token <"$wrapper_link_output"
if [[ $wrapper_link_status -eq 2 && $wrapper_link_token == POLICY_ERROR ]]; then
    record_pass "symlinked wrapper rejected"
else
    record_fail "symlinked wrapper rejected"
fi

environment_policy="$HARNESS_DIR/environment-policy"
make_policy_copy "$environment_policy"
environment_output="$HARNESS_DIR/environment-output"
"$ENV_BIN" -i PATH="$SENTINEL_DIR:$CLEAN_PATH" HOME="$HOME_DIR" LC_ALL=C \
    NULLSEC_WOLT_POLICY_DIR="$environment_policy" \
    NULLSEC_WOLT_TEST_POLICY_DIR="$environment_policy" \
    "$BASH_BIN" "$ISOLATED_WRAPPER" --classify wolt.com \
    >"$environment_output" 2>/dev/null
environment_status=$?
IFS= builtin read -r environment_token <"$environment_output"
if [[ $environment_status -eq 0 && $environment_token == APPROVED_EXACT ]]; then
    record_pass "environment cannot redirect production policy"
else
    record_fail "environment cannot redirect production policy"
fi

for option in --run --scan; do
    clean_invoke "$option" wolt.com >/dev/null 2>/dev/null
    option_status=$?
    if [[ $option_status -eq 64 ]]; then
        record_pass "unsupported option rejected: $option"
    else
        record_fail "unsupported option rejected: $option"
    fi
done

snapshot_before="$HARNESS_DIR/snapshot-before"
snapshot_after="$HARNESS_DIR/snapshot-after"
snapshot_tree "$ISOLATED_REPO" "$snapshot_before"
clean_invoke --classify wolt.com >/dev/null 2>/dev/null
snapshot_status=$?
clean_invoke --show-policy >/dev/null 2>/dev/null
show_status=$?
snapshot_tree "$ISOLATED_REPO" "$snapshot_after"
if [[ $snapshot_status -eq 0 && $show_status -eq 0 ]] &&
   /usr/bin/cmp -s "$snapshot_before" "$snapshot_after"; then
    record_pass "wrapper creates or modifies no repository output"
else
    record_fail "wrapper creates or modifies no repository output"
fi

if [[ ! -e $SENTINEL_LOG ]]; then
    record_pass "no network-capable PATH command invoked"
else
    record_fail "no network-capable PATH command invoked"
fi
if [[ ! -e $NULLSEC_SENTINEL_LOG ]]; then
    record_pass "isolated nullsec.sh never invoked"
else
    record_fail "isolated nullsec.sh never invoked"
fi

builtin printf '# pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
((FAIL == 0))
