#!/bin/bash
#
# NullSec Wolt Stage 1 offline safety wrapper.
#
# This wrapper validates immutable local policy and classifies local input.
# It never sources or invokes nullsec.sh, performs reconnaissance, resolves DNS,
# makes HTTP requests, sends notifications, updates tools, or creates output.

set -uo pipefail
LC_ALL=C
export LC_ALL
umask 077

readonly EXIT_APPROVED=0
readonly EXIT_POLICY_ERROR=2
readonly EXIT_INPUT_ERROR=3
readonly EXIT_USAGE=64
readonly EXIT_PENDING=10
readonly EXIT_EXCLUDED=11
readonly EXIT_NON_WOLT=12
readonly EXIT_MOBILE=13
readonly EXIT_MALFORMED=14
readonly EXIT_FILE_CONTAINS_NONAPPROVED=20

readonly TOKEN_APPROVED=APPROVED_EXACT
readonly TOKEN_PENDING=PENDING_WILDCARD_REVIEW
readonly TOKEN_EXCLUDED=EXCLUDED
readonly TOKEN_NON_WOLT=NON_WOLT
readonly TOKEN_MOBILE=MOBILE_ASSET
readonly TOKEN_MALFORMED=MALFORMED
readonly TOKEN_POLICY_ERROR=POLICY_ERROR
readonly TOKEN_INPUT_ERROR=INPUT_ERROR

PROGRAM_NAME=${0##*/}
POLICY_FAILURE_CODE=
POLICY_JSON_CONTENT=
POLICY_VALIDATED=false

declare -A APPROVED_SET=()
declare -A EXCLUDED_SET=()
declare -A MOBILE_SET=()

readonly -a EXPECTED_APPROVED=(
    "wolt.com"
    "restaurant-api.wolt.com"
    "ops.wolt.com"
    "merchant.wolt.com"
    "drive.wolt.com"
    "corporate.wolt.com"
    "authentication.wolt.com"
)

readonly -a EXPECTED_EXCLUDED=(
    "wolt.atlassian.net"
    "press.wolt.com"
    "links.wolt.com"
    "gettest.wolt.com"
    "blog.wolt.com"
)

readonly -a EXPECTED_MOBILE=(
    "com.wolt.courierapp"
    "com.wolt.android"
    "943905271"
    "1477299281"
)

resolve_wrapper_directory() {
    local source_path=${BASH_SOURCE[0]}
    local source_directory

    if [[ -L $source_path ]]; then
        return 1
    fi

    case $source_path in
        */*) source_directory=${source_path%/*} ;;
        *) source_directory=. ;;
    esac

    if ! builtin cd -P -- "$source_directory"; then
        return 1
    fi

    WRAPPER_DIR=$PWD
    readonly WRAPPER_DIR
    return 0
}

if ! resolve_wrapper_directory; then
    builtin printf '%s\n' "$TOKEN_POLICY_ERROR"
    exit "$EXIT_POLICY_ERROR"
fi

PRODUCTION_POLICY_DIR="$WRAPPER_DIR/config"
POLICY_DIR=$PRODUCTION_POLICY_DIR

usage() {
    builtin printf '%s\n' \
        "Usage:" \
        "  $PROGRAM_NAME --classify <single-asset>" \
        "  $PROGRAM_NAME --classify-file <local-regular-file>" \
        "  $PROGRAM_NAME --show-policy" \
        "  $PROGRAM_NAME --help" \
        "" \
        "Classification tokens and exit codes:" \
        "  APPROVED_EXACT               0" \
        "  PENDING_WILDCARD_REVIEW     10" \
        "  EXCLUDED                    11" \
        "  NON_WOLT                    12" \
        "  MOBILE_ASSET                13" \
        "  MALFORMED                   14" \
        "" \
        "Other deterministic exit codes:" \
        "  POLICY_ERROR                 2" \
        "  INPUT_ERROR                  3" \
        "  classification file contains" \
        "    a non-approved entry      20" \
        "  command-line usage error    64" \
        "" \
        "Each classification request emits exactly one fixed token." \
        "Classification files emit one fixed token per input line." \
        "Stage 1 is offline-only and performs no security testing."
}

policy_fail() {
    POLICY_FAILURE_CODE=$1
    return 1
}

report_policy_failure() {
    builtin printf '%s\n' "$TOKEN_POLICY_ERROR"
    builtin printf 'policy validation failed: %s\n' \
        "${POLICY_FAILURE_CODE:-unspecified}" >&2
}

report_input_failure() {
    builtin printf '%s\n' "$TOKEN_INPUT_ERROR"
}

configure_policy_directory() {
    local requested_directory=$1

    if [[ -z $requested_directory ]]; then
        policy_fail test_policy_directory_empty
        return 1
    fi

    if [[ -L $requested_directory ]]; then
        policy_fail test_policy_directory_symlink
        return 1
    fi

    if [[ ! -d $requested_directory || ! -r $requested_directory ]]; then
        policy_fail test_policy_directory_invalid
        return 1
    fi

    # Explicit test-only policy injection. No environment variable can enable it.
    POLICY_DIR=$requested_directory
    return 0
}

set_policy_paths() {
    APPROVED_FILE="$POLICY_DIR/wolt-approved-exact.txt"
    EXCLUDED_FILE="$POLICY_DIR/wolt-excluded.txt"
    MOBILE_FILE="$POLICY_DIR/wolt-mobile-assets.txt"
    POLICY_JSON_FILE="$POLICY_DIR/wolt-policy.json"

    readonly APPROVED_FILE
    readonly EXCLUDED_FILE
    readonly MOBILE_FILE
    readonly POLICY_JSON_FILE
}

validate_local_regular_file() {
    local file=$1
    local purpose=$2

    if [[ -L $file ]]; then
        policy_fail "${purpose}_symlink"
        return 1
    fi

    if [[ ! -f $file ]]; then
        policy_fail "${purpose}_missing_or_nonregular"
        return 1
    fi

    if [[ ! -x /usr/bin/python3 ]]; then
        policy_fail python3_unavailable
        return 1
    fi

    # Validate raw bytes before Bash reads them. LF is the only permitted
    # control byte. Permission bits are checked so mode 000 fails under root.
    if ! /usr/bin/python3 -I -S -c '
import os
import stat
import sys

path = sys.argv[1]
try:
    metadata = os.lstat(path)
except OSError:
    raise SystemExit(10)
if stat.S_ISLNK(metadata.st_mode):
    raise SystemExit(11)
if not stat.S_ISREG(metadata.st_mode):
    raise SystemExit(12)
if metadata.st_mode & 0o444 == 0:
    raise SystemExit(13)
try:
    with open(path, "rb") as handle:
        data = handle.read()
except OSError:
    raise SystemExit(14)
if not data:
    raise SystemExit(15)
if b"\x00" in data:
    raise SystemExit(16)
if any(byte > 0x7f for byte in data):
    raise SystemExit(17)
if any((byte < 0x20 and byte != 0x0a) or byte == 0x7f for byte in data):
    raise SystemExit(18)
' "$file" >/dev/null 2>&1; then
        policy_fail "${purpose}_raw_bytes_invalid"
        return 1
    fi

    return 0
}

validate_input_regular_file() {
    local file=$1

    if [[ $file == "-" || -L $file || ! -f $file ]]; then
        return 1
    fi

    if [[ ! -x /usr/bin/python3 ]]; then
        return 1
    fi

    if ! /usr/bin/python3 -I -S -c '
import os
import stat
import sys

path = sys.argv[1]
try:
    metadata = os.lstat(path)
except OSError:
    raise SystemExit(10)
if stat.S_ISLNK(metadata.st_mode):
    raise SystemExit(11)
if not stat.S_ISREG(metadata.st_mode):
    raise SystemExit(12)
if metadata.st_mode & 0o444 == 0:
    raise SystemExit(13)
try:
    with open(path, "rb") as handle:
        data = handle.read()
except OSError:
    raise SystemExit(14)
if not data:
    raise SystemExit(15)
if b"\x00" in data:
    raise SystemExit(16)
if any(byte > 0x7f for byte in data):
    raise SystemExit(17)
if any((byte < 0x20 and byte != 0x0a) or byte == 0x7f for byte in data):
    raise SystemExit(18)
' "$file" >/dev/null 2>&1; then
        return 1
    fi

    return 0
}

contains_non_ascii_or_control() {
    local value=$1
    local index character numeric

    for ((index = 0; index < ${#value}; index++)); do
        character=${value:index:1}
        builtin printf -v numeric '%d' "'$character"
        if ((numeric < 32 || numeric > 126)); then
            return 0
        fi
    done

    return 1
}

contains_rejected_component_character() {
    local value=$1

    case $value in
        *'/'*|*':'*|*'?'*|*'#'*|*'@'*|*'\'*|\
        *'*'*|*';'*|*'&'*|*'|'*|*'`'*|*'$'*|\
        *'<'*|*'>'*|*'('*|*')'*|*'{'*|*'}'*|\
        *'['*|*']'*|*'"'*|*"'"*|*'!'*)
            return 0
            ;;
    esac

    return 1
}

is_mobile_asset() {
    local value=$1

    if [[ -n ${MOBILE_SET[$value]+present} ]]; then
        return 0
    fi

    if [[ $value =~ ^com\.wolt\.[a-z0-9_]+([.][a-z0-9_]+)*$ ]]; then
        return 0
    fi

    return 1
}

is_numeric_dotted_form() {
    local value=$1

    if [[ $value == *.* && $value =~ ^[0-9.]+$ ]]; then
        return 0
    fi

    return 1
}

is_valid_ascii_hostname() {
    local hostname=$1
    local remainder label

    if [[ -z $hostname || ${#hostname} -gt 253 ]]; then
        return 1
    fi
    if [[ $hostname != *.* ]]; then
        return 1
    fi
    if [[ $hostname == .* || $hostname == *. || $hostname == *..* ]]; then
        return 1
    fi
    if [[ ! $hostname =~ ^[a-z0-9.-]+$ ]]; then
        return 1
    fi
    if is_numeric_dotted_form "$hostname"; then
        return 1
    fi

    remainder=$hostname
    while :; do
        if [[ $remainder == *.* ]]; then
            label=${remainder%%.*}
            remainder=${remainder#*.}
        else
            label=$remainder
            remainder=
        fi

        if [[ -z $label || ${#label} -gt 63 ]]; then
            return 1
        fi
        if [[ ! $label =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]]; then
            return 1
        fi
        if [[ $label == xn--* ]]; then
            return 1
        fi
        if [[ -z $remainder ]]; then
            break
        fi
    done

    return 0
}

load_policy_list() {
    local file=$1
    local purpose=$2
    local output_name=$3
    local -n output=$output_name
    local -A seen=()
    local line
    local line_number=0

    if ! validate_local_regular_file "$file" "$purpose"; then
        return 1
    fi

    while IFS= read -r line || [[ -n $line ]]; do
        ((line_number += 1))

        if [[ -z $line ]]; then
            policy_fail "${purpose}_empty_entry"
            return 1
        fi
        if contains_non_ascii_or_control "$line"; then
            policy_fail "${purpose}_invalid_bytes"
            return 1
        fi
        if [[ $line == *[[:space:]]* ]]; then
            policy_fail "${purpose}_whitespace"
            return 1
        fi
        if [[ $line != "${line,,}" ]]; then
            policy_fail "${purpose}_noncanonical_case"
            return 1
        fi
        if [[ -n ${seen[$line]+present} ]]; then
            policy_fail "${purpose}_duplicate"
            return 1
        fi

        case $purpose in
            approved|excluded)
                if contains_rejected_component_character "$line"; then
                    policy_fail "${purpose}_component_character"
                    return 1
                fi
                if ! is_valid_ascii_hostname "$line"; then
                    policy_fail "${purpose}_malformed_hostname"
                    return 1
                fi
                ;;
            mobile)
                case $line in
                    com.wolt.courierapp|com.wolt.android|943905271|1477299281)
                        ;;
                    *)
                        policy_fail mobile_unknown_asset
                        return 1
                        ;;
                esac
                ;;
            *)
                policy_fail internal_policy_type
                return 1
                ;;
        esac

        seen["$line"]=1
        output["$line"]=1
    done <"$file"

    if ((line_number == 0)); then
        policy_fail "${purpose}_empty_file"
        return 1
    fi

    return 0
}

validate_expected_set() {
    local purpose=$1
    local expected_name=$2
    local actual_name=$3
    local -n expected=$expected_name
    local -n actual=$actual_name
    local entry

    if ((${#actual[@]} != ${#expected[@]})); then
        policy_fail "${purpose}_count_mismatch"
        return 1
    fi

    for entry in "${expected[@]}"; do
        if [[ -z ${actual[$entry]+present} ]]; then
            policy_fail "${purpose}_missing_required"
            return 1
        fi
    done

    return 0
}

validate_cross_policy_conflicts() {
    local entry

    for entry in "${!APPROVED_SET[@]}"; do
        if [[ -n ${EXCLUDED_SET[$entry]+present} ]]; then
            policy_fail approved_excluded_conflict
            return 1
        fi
        if [[ -n ${MOBILE_SET[$entry]+present} ]]; then
            policy_fail approved_mobile_conflict
            return 1
        fi
    done

    for entry in "${!EXCLUDED_SET[@]}"; do
        if [[ -n ${MOBILE_SET[$entry]+present} ]]; then
            policy_fail excluded_mobile_conflict
            return 1
        fi
    done

    return 0
}

validate_json_policy() {
    if ! validate_local_regular_file "$POLICY_JSON_FILE" json_policy; then
        return 1
    fi

    if ! /usr/bin/python3 -I -S -c '
import json
import sys

class DuplicateKey(Exception):
    pass

def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKey(key)
        result[key] = value
    return result

expected = {
    "schema_version": 1,
    "program": "Wolt HackerOne bug bounty",
    "stage": 1,
    "offline_only": True,
    "nullsec_execution_allowed": False,
    "network_execution_allowed": False,
    "wildcard": {
        "policy_asset": "*.wolt.com",
        "passive_discovery_seed": "wolt.com",
        "literal_wildcard_may_be_passed_to_tools": False,
        "discovered_hosts_require_review": True
    },
    "approved_exact_web_assets": [
        "wolt.com",
        "restaurant-api.wolt.com",
        "ops.wolt.com",
        "merchant.wolt.com",
        "drive.wolt.com",
        "corporate.wolt.com",
        "authentication.wolt.com"
    ],
    "explicit_exclusions": [
        "wolt.atlassian.net",
        "press.wolt.com",
        "links.wolt.com",
        "gettest.wolt.com",
        "blog.wolt.com"
    ],
    "mobile_assets": [
        "com.wolt.courierapp",
        "com.wolt.android",
        "943905271",
        "1477299281"
    ],
    "precedence": [
        "malformed",
        "mobile_asset",
        "explicit_exclusion",
        "approved_exact",
        "wildcard_eligible_pending_review",
        "non_wolt"
    ],
    "future_http_requirements": {
        "required_header_name": "X-HackerOne-Research",
        "header_enabled_in_stage_1": False,
        "username_must_reject_cr_lf": True,
        "username_must_reject_header_injection": True
    },
    "account_and_data_rules": {
        "researcher_owned_accounts_and_data_only": True,
        "customer_accounts_may_be_self_registered": True,
        "courier_accounts_available": False,
        "merchant_accounts_available": False,
        "designated_test_entities_required_where_applicable": True
    },
    "prohibited_testing": [
        "payment-processor testing",
        "brute force",
        "DoS or DDoS",
        "web-cache poisoned denial-of-service",
        "spam or social engineering",
        "physical intrusion",
        "email bombing",
        "mass account or entity creation",
        "victim-device attacks",
        "data modification outside researcher-owned test data"
    ]
}

try:
    with open(sys.argv[1], "r", encoding="ascii", newline="") as handle:
        actual = json.load(handle, object_pairs_hook=reject_duplicates)
except (OSError, UnicodeError, json.JSONDecodeError, DuplicateKey):
    raise SystemExit(20)

if actual != expected:
    raise SystemExit(21)
' "$POLICY_JSON_FILE" >/dev/null 2>&1; then
        policy_fail json_policy_semantic_mismatch
        return 1
    fi

    POLICY_JSON_CONTENT=
    if ! IFS= builtin read -r -d '' POLICY_JSON_CONTENT <"$POLICY_JSON_FILE"; then
        if [[ -z $POLICY_JSON_CONTENT ]]; then
            policy_fail json_policy_read_failed
            return 1
        fi
    fi

    return 0
}

validate_policy() {
    if [[ $POLICY_VALIDATED == true ]]; then
        return 0
    fi

    APPROVED_SET=()
    EXCLUDED_SET=()
    MOBILE_SET=()

    if ! load_policy_list "$APPROVED_FILE" approved APPROVED_SET; then
        return 1
    fi
    if ! load_policy_list "$EXCLUDED_FILE" excluded EXCLUDED_SET; then
        return 1
    fi
    if ! load_policy_list "$MOBILE_FILE" mobile MOBILE_SET; then
        return 1
    fi
    if ! validate_cross_policy_conflicts; then
        return 1
    fi
    if ! validate_expected_set approved EXPECTED_APPROVED APPROVED_SET; then
        return 1
    fi
    if ! validate_expected_set excluded EXPECTED_EXCLUDED EXCLUDED_SET; then
        return 1
    fi
    if ! validate_expected_set mobile EXPECTED_MOBILE MOBILE_SET; then
        return 1
    fi
    if ! validate_json_policy; then
        return 1
    fi

    POLICY_VALIDATED=true
    return 0
}

classify() {
    local raw=$1
    local canonical

    if [[ -z $raw ]]; then
        builtin printf '%s\n' "$TOKEN_MALFORMED"
        return "$EXIT_MALFORMED"
    fi
    if contains_non_ascii_or_control "$raw"; then
        builtin printf '%s\n' "$TOKEN_MALFORMED"
        return "$EXIT_MALFORMED"
    fi
    if [[ $raw == *[[:space:]]* ]]; then
        builtin printf '%s\n' "$TOKEN_MALFORMED"
        return "$EXIT_MALFORMED"
    fi
    if contains_rejected_component_character "$raw"; then
        builtin printf '%s\n' "$TOKEN_MALFORMED"
        return "$EXIT_MALFORMED"
    fi
    if [[ $raw == -* ]]; then
        builtin printf '%s\n' "$TOKEN_MALFORMED"
        return "$EXIT_MALFORMED"
    fi

    canonical=${raw,,}

    if is_mobile_asset "$canonical"; then
        builtin printf '%s\n' "$TOKEN_MOBILE"
        return "$EXIT_MOBILE"
    fi
    if [[ $canonical =~ ^[0-9]+$ ]]; then
        builtin printf '%s\n' "$TOKEN_MALFORMED"
        return "$EXIT_MALFORMED"
    fi
    if [[ $canonical == *. ]]; then
        canonical=${canonical%.}
    fi
    if ! is_valid_ascii_hostname "$canonical"; then
        builtin printf '%s\n' "$TOKEN_MALFORMED"
        return "$EXIT_MALFORMED"
    fi

    # Exclusions override both exact approval and wildcard eligibility.
    if [[ -n ${EXCLUDED_SET[$canonical]+present} ]]; then
        builtin printf '%s\n' "$TOKEN_EXCLUDED"
        return "$EXIT_EXCLUDED"
    fi
    if [[ -n ${APPROVED_SET[$canonical]+present} ]]; then
        builtin printf '%s\n' "$TOKEN_APPROVED"
        return "$EXIT_APPROVED"
    fi
    if [[ $canonical == *.wolt.com ]]; then
        builtin printf '%s\n' "$TOKEN_PENDING"
        return "$EXIT_PENDING"
    fi

    builtin printf '%s\n' "$TOKEN_NON_WOLT"
    return "$EXIT_NON_WOLT"
}

classify_file() {
    local file=$1
    local line
    local line_status
    local aggregate_status=$EXIT_APPROVED
    local line_count=0

    if ! validate_input_regular_file "$file"; then
        report_input_failure
        return "$EXIT_INPUT_ERROR"
    fi

    while IFS= read -r line || [[ -n $line ]]; do
        ((line_count += 1))
        classify "$line"
        line_status=$?
        if ((line_status != EXIT_APPROVED)); then
            aggregate_status=$EXIT_FILE_CONTAINS_NONAPPROVED
        fi
    done <"$file"

    if ((line_count == 0)); then
        report_input_failure
        return "$EXIT_INPUT_ERROR"
    fi

    return "$aggregate_status"
}

main() {
    local command=${1:-}

    if [[ $command == "--test-policy-dir" ]]; then
        if (($# < 3)); then
            builtin printf '%s\n' "$TOKEN_POLICY_ERROR"
            return "$EXIT_POLICY_ERROR"
        fi
        if ! configure_policy_directory "$2"; then
            report_policy_failure
            return "$EXIT_POLICY_ERROR"
        fi
        shift 2
        command=${1:-}
    fi

    set_policy_paths

    case $command in
        --help)
            if (($# != 1)); then
                usage >&2
                return "$EXIT_USAGE"
            fi
            usage
            return 0
            ;;
        --classify)
            if (($# != 2)); then
                usage >&2
                return "$EXIT_USAGE"
            fi
            if ! validate_policy; then
                report_policy_failure
                return "$EXIT_POLICY_ERROR"
            fi
            classify "$2"
            return $?
            ;;
        --classify-file)
            if (($# != 2)); then
                usage >&2
                return "$EXIT_USAGE"
            fi
            if ! validate_policy; then
                report_policy_failure
                return "$EXIT_POLICY_ERROR"
            fi
            classify_file "$2"
            return $?
            ;;
        --show-policy)
            if (($# != 1)); then
                usage >&2
                return "$EXIT_USAGE"
            fi
            if ! validate_policy; then
                report_policy_failure
                return "$EXIT_POLICY_ERROR"
            fi
            builtin printf '%s\n' "$POLICY_JSON_CONTENT"
            return 0
            ;;
        *)
            usage >&2
            return "$EXIT_USAGE"
            ;;
    esac
}

main "$@"
