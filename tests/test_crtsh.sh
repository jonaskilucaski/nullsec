#!/usr/bin/env bash
# Offline regression tests: extract only the crt.sh block and its scope helpers.
# authorized_run is mocked; curl and the reconnaissance entry point never run.
set -uo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
script="${1:-$repo_dir/nullsec.sh}"
command -v jq >/dev/null || { printf 'jq is required\n' >&2; exit 1; }
work_dir=$(mktemp -d) || exit 1
trap 'rm -rf -- "$work_dir"' EXIT

for helper in count_lines _valid_policy_host normalize_scope_input \
    _host_rule_matches scope_host_excluded scope_host_allowed in_scope; do
    definition=$(awk -v name="$helper" '
        $0 == name "() {" { found = 1 }
        found { print }
        found && /^}$/ { exit }
    ' "$script")
    [ -n "$definition" ] || exit 1
    eval "$definition"
done
eval "crtsh_block() {
$(sed -n '/^    info "Querying crt.sh /,/^    info "Merging passive enumeration results/ {
    /Merging passive enumeration results/!p
}' "$script")
}"
declare -f crtsh_block | grep -Eq 'authorized_run passive service' || exit 1

info() { printf 'INFO: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*"; }
success() { printf 'SUCCESS: %s\n' "$*"; }
fail() { printf 'FAIL: %s: %s\n' "$case_name" "$*" >&2; exit 1; }

authorized_run() {
    # Assert that authorization, HTTPS, redirect, timeout and retry guards remain.
    local url="https://crt.sh/?q=%25.$TARGET&output=json"
    local -a expected=(passive service "$url" curl -q --proto '=https'
        --max-redirs 0 -sS --connect-timeout 10 --max-time 45 --retry 4
        --retry-delay 5 --retry-max-time 180 --retry-all-errors
        -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        -o "$p1dir/.crtsh-response.tmp.$$" -w '%{http_code}' "$url")
    [ "$#" -eq "${#expected[@]}" ] || return 90
    local arg
    for arg in "${expected[@]}"; do
        [ "$1" = "$arg" ] || return 90
        shift
    done
    printf 'called\n' > "$p1dir/request-called"
    printf '%s' "$response" > "$p1dir/.crtsh-response.tmp.$$" || return 91
    printf '%s' "$http_code"
    return "$request_rc"
}

mv() {
    [ "$case_name" != save_failure ] || return 1
    command mv "$@"
}

sort() {
    if [ "$case_name" = sort_failure ]; then
        cat
        return 1
    fi
    command sort "$@"
}

run_case() (
    local case_name="$1" outcome="$2" expected="$3" initial="${4:-previous}"
    local p1dir="$work_dir/$case_name" phase_errors=0
    local TARGET=example.com POLICY_READY=true
    local INCLUDE_RULES='*.example.com' EXCLUDE_RULES=excluded.example.com
    local response='[{"name_value":"B.EXAMPLE.COM\n*.a.example.com\na.example.com\nother.test\nexcluded.example.com"}]'
    local http_code=200 request_rc=0
    mkdir -p -- "$p1dir" || fail 'fixture creation failed'
    case "$initial" in
        previous) printf 'prior.example.com\n' > "$p1dir/crtsh.txt" ;;
        directory) mkdir "$p1dir/crtsh.txt" ;;
        missing) ;;
    esac
    case "$case_name" in
        empty) response='[]' ;;
        http_502*) http_code=502 ;;
        malformed) response='[{"name_value":' ;;
        wrong_shape) response='{}' ;;
        parsing_failure) response='[{"name_value":"partial.example.com"},42]' ;;
        request_failure) request_rc=28 ;;
        scope_failure) POLICY_READY=false ;;
    esac

    crtsh_block > "$p1dir/status.log" 2> "$p1dir/stderr.log"
    [ "$?" -eq 0 ] || fail 'optional source returned a failure status'
    [ "$phase_errors" -eq 0 ] || fail 'optional source increased phase_errors'
    [ -f "$p1dir/request-called" ] || fail 'request safeguards changed'
    if [ "$outcome" = success ]; then
        grep -Eqx "SUCCESS: crt.sh: $expected subdomains" "$p1dir/status.log" \
            || fail 'missing success message or incorrect count'
        ! grep -Eq '^WARN:' "$p1dir/status.log" || fail 'unexpected warning'
        if [ "$case_name" = empty ]; then
            [ -f "$p1dir/crtsh.txt" ] && [ ! -s "$p1dir/crtsh.txt" ] \
                || fail 'empty results did not replace prior output'
        else
            printf 'a.example.com\nb.example.com\n' > "$p1dir/expected.txt"
            cmp -s "$p1dir/expected.txt" "$p1dir/crtsh.txt" \
                || fail 'normalization, deduplication or scope filtering changed'
        fi
    else
        ! grep -Eq '^SUCCESS:' "$p1dir/status.log" || fail 'misleading success message'
        grep -Eq '^WARN: crt.sh.*keeping previous results' "$p1dir/status.log" \
            || fail 'missing failure warning'
        case "$initial" in
            previous)
                printf 'prior.example.com\n' > "$p1dir/expected.txt"
                cmp -s "$p1dir/expected.txt" "$p1dir/crtsh.txt" \
                    || fail 'previous results changed' ;;
            directory)
                [ -d "$p1dir/crtsh.txt" ] || fail 'destination directory changed'
                [ -z "$(ls -A "$p1dir/crtsh.txt")" ] \
                    || fail 'results were moved inside destination directory' ;;
            missing)
                [ -f "$p1dir/crtsh.txt" ] && [ ! -s "$p1dir/crtsh.txt" ] \
                    || fail 'missing empty placeholder for subsequent merge' ;;
        esac
    fi
    local -a leftovers=("$p1dir"/.crtsh-*.tmp.*)
    [ ! -e "${leftovers[0]}" ] || fail 'temporary files were not cleaned up'
    printf 'PASS: %s\n' "$case_name"
)

run_case valid_results success 2 || exit 1
run_case empty success 0 || exit 1
run_case http_502 failure 0 || exit 1
run_case http_502_missing failure 0 missing || exit 1
run_case malformed failure 0 || exit 1
run_case wrong_shape failure 0 || exit 1
run_case parsing_failure failure 0 || exit 1
run_case scope_failure failure 0 || exit 1
run_case sort_failure failure 0 || exit 1
run_case save_failure failure 0 || exit 1
run_case destination_directory failure 0 directory || exit 1
run_case request_failure failure 0 || exit 1
