#!/usr/bin/env bash
# Offline regressions: load selected functions, never the framework entry point.
# Scanner commands, template identity persistence and checkpoint I/O are mocked.
# The real authorization/scope gates, scan wrapper and phase runner are exercised.
set -uo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
script="${1:-$repo_dir/nullsec.sh}"
work_dir=$(mktemp -d) || exit 1
trap 'rm -rf -- "$work_dir"' EXIT

for helper in count_lines _valid_policy_host normalize_scope_input \
    _host_rule_matches scope_host_excluded scope_host_allowed in_scope \
    authorization_allowed authorized_run apply_scan_mode nuclei_target_scan \
    phase2_validation _run_generation_phase; do
    definition=$(awk -v name="$helper" '
        $0 == name "() {" || $0 == name "() (" { found = 1 }
        found { print }
        found && /^[})]$/ { exit }
    ' "$script")
    [ -n "$definition" ] || { printf 'Missing function: %s\n' "$helper" >&2; exit 1; }
    eval "$definition"
done

info() { printf 'INFO: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*"; }
success() { printf 'SUCCESS: %s\n' "$*"; }
error() { printf 'ERROR: %s\n' "$*"; }
state_error() { error "$@"; return 1; }
print_phase() { :; }
polite_sleep() { :; }
phase_done() { return 1; }
validate_output_tree() { return 0; }
backup_phase_outputs() { return 0; }
merge_phase_backup() { touch "$OUTPUT_DIR/merged"; }
prepare_phase_outputs() { mkdir -p -- "$1"; }
_phase_dir() { printf '%s/phase2-validation\n' "$OUTPUT_DIR"; }
_phase_has_results() { [ -s "$OUTPUT_DIR/phase2-validation/valid-subdomains.txt" ]; }
_phase_digest() { printf '%064d\n' 0; }
_write_phase_state() { printf '%s\n' "$2" >> "$OUTPUT_DIR/states"; }
save_checkpoint() { printf '%s\n' "$1" > "$OUTPUT_DIR/checkpoint"; }
_skip_phase() { PHASE_SKIPPED=true; }
nuclei_template_identity() { printf 'SELECTED=%s\nSEVERITY=%s\n' "$1" "$NUCLEI_SEVERITY"; }
_atomic_state_write() {
    [ "$case_name" != identity_failure ] || return 1
    cat > "$1"
}

fail() { printf 'FAIL: %s: %s\n' "$case_name" "$*" >&2; exit 1; }

# These shell functions are the only implementations of the scanner commands
# reachable from the extracted code. Neither invokes an external scanner.
dnsx() {
    local input="" output=""
    while [ "$#" -gt 0 ]; do
        case "$1" in -l) input="$2"; shift ;; -o) output="$2"; shift ;; esac
        shift
    done
    [ -n "$input" ] && [ -n "$output" ] || return 90
    cmp -s "$input" "$OUTPUT_DIR/expected-targets" || return 91
    printf 'app.example.com [A] [192.0.2.1]\n' > "$output"
}

nuclei() {
    local input="" output="" templates="" severity="" arg file level selected=0 duc=false
    printf '%s\n' "$@" > "$OUTPUT_DIR/nuclei-args"
    while [ "$#" -gt 0 ]; do
        arg="$1"
        case "$arg" in
            -l) input="$2"; shift ;;
            -o) output="$2"; shift ;;
            -t) templates="$2"; shift ;;
            -severity) severity="$2"; shift ;;
            -duc) duc=true ;;
        esac
        shift
    done
    [ "$duc" = true ] && [ -n "$input" ] && [ -n "$output" ] && [ -d "$templates" ] || return 90
    cmp -s "$input" "$OUTPUT_DIR/expected-targets" || return 91
    cp -- "$input" "$OUTPUT_DIR/nuclei-targets"
    : > "$OUTPUT_DIR/selected-templates"
    # Model Nuclei's intersection of explicit template paths and -severity.
    # The takeover fixtures deliberately have no Critical templates.
    while IFS= read -r file; do
        level=$(awk '$1 == "severity:" { print $2 }' "$file")
        if [ -z "$severity" ] || [[ ",$severity," == *",$level,"* ]]; then
            printf '%s\n' "$file" >> "$OUTPUT_DIR/selected-templates"
            selected=$((selected + 1))
        fi
    done < <(find "$templates" -type f -name '*.yaml' | LC_ALL=C sort)
    if [ "$selected" -eq 0 ]; then
        printf 'no templates provided for scan\n' >&2
        return 2
    fi
    case "$case_name" in
        findings|partial_failure) printf '[takeover] [http] [high] app.example.com\n' > "$output" ;;
    esac
    case "$case_name" in
        scan_failure|partial_failure) printf 'offline scanner failure\n' >&2; return 23 ;;
    esac
}

run_case() (
    local mode="$1" case_name="$2" expected_severity expected_count rc=0 level
    local OUTPUT_DIR="$work_dir/$mode-$case_name" NUCLEI_TEMPLATES="$work_dir/$mode-$case_name/templates"
    local TARGET=example.com POLICY_READY=true ALLOW_ACTIVE_ENUM=true ALLOW_ACTIVE_VALIDATION=true
    local INCLUDE_RULES=$'example.com\napp.example.com\nblocked.example.com' EXCLUDE_RULES=blocked.example.com
    local GENERATION_ID STATE_FAILED=false CHECKPOINT_FROZEN=false RESUME_FROM=1
    local SCAN_MODE="$mode" NULLSEC_AMASS_TIMEOUT=""
    GENERATION_ID=$(printf '%064d' 0)
    mkdir -p -- "$OUTPUT_DIR/phase1-subdomains" "$OUTPUT_DIR/phase2-validation" \
        "$NUCLEI_TEMPLATES/http/takeovers" || fail 'fixture creation failed'
    printf 'app.example.com\nblocked.example.com\nchild.app.example.com\nother.test\napp.example.com.evil.test\n' \
        > "$OUTPUT_DIR/phase1-subdomains/all-subdomains.txt"
    printf 'app.example.com\n' > "$OUTPUT_DIR/expected-targets"
    printf '1\n' > "$OUTPUT_DIR/checkpoint"
    for level in high medium low info unknown; do
        printf 'id: takeover-%s\ninfo:\n  severity: %s\n' "$level" "$level" \
            > "$NUCLEI_TEMPLATES/http/takeovers/$level.yaml"
    done
    printf 'id: general-critical\ninfo:\n  severity: critical\n' > "$NUCLEI_TEMPLATES/critical.yaml"
    apply_scan_mode > "$OUTPUT_DIR/mode.log"
    case "$mode" in
        fast) expected_severity=critical; expected_count=1 ;;
        normal) expected_severity=critical,high,medium; expected_count=3 ;;
        deep) expected_severity=critical,high,medium,low; expected_count=4 ;;
    esac
    [ "$NUCLEI_SEVERITY" = "$expected_severity" ] || fail 'mode preset changed'
    case "$case_name" in
        validation_denied) ALLOW_ACTIVE_VALIDATION=false ;;
        enumeration_denied) ALLOW_ACTIVE_ENUM=false ;;
        policy_unready) POLICY_READY=false ;;
        missing_templates) mv -- "$NUCLEI_TEMPLATES/http/takeovers" "$NUCLEI_TEMPLATES/http/unselected" ;;
        missing_root) NUCLEI_TEMPLATES="$OUTPUT_DIR/missing" ;;
    esac

    _run_generation_phase 2 phase2_validation > "$OUTPUT_DIR/status.log" 2> "$OUTPUT_DIR/stderr.log" || rc=$?
    [ "$NUCLEI_SEVERITY" = "$expected_severity" ] || fail 'takeover override leaked into the mode preset'
    local status_log="$OUTPUT_DIR/status.log" p2dir="$OUTPUT_DIR/phase2-validation"
    case "$case_name" in
        scan_failure|partial_failure|identity_failure)
            [ "$rc" -ne 0 ] || fail 'scan failure did not fail the phase'
            [ "$CHECKPOINT_FROZEN" = true ] || fail 'scan failure did not freeze checkpoint advancement'
            [ "$(cat "$OUTPUT_DIR/checkpoint")" = 1 ] || fail 'failed phase advanced checkpoint'
            [ "$(tail -n 1 "$OUTPUT_DIR/states")" = failed ] || fail 'failed phase status was not recorded'
            grep -q 'inconclusive' "$status_log" || fail 'missing inconclusive status'
            grep -q 'checkpoint was not advanced' "$status_log" || fail 'missing phase error warning'
            ! grep -Eq 'No takeover vulnerabilities detected|Potential takeover vulnerabilities found|Phase 2 complete!' \
                "$status_log" || fail 'scan failure reported a successful result'
            [ -f "$OUTPUT_DIR/merged" ] || fail 'failure skipped backup merge'
            if [ "$case_name" != identity_failure ]; then
                grep -qx 'offline scanner failure' "$p2dir/takeover-nuclei.log" || fail 'scanner stderr lost'
            else
                [ ! -e "$OUTPUT_DIR/nuclei-args" ] || fail 'scan ran after identity persistence failure'
            fi
            if [ "$case_name" = partial_failure ]; then
                [ -s "$p2dir/takeover-findings.txt" ] || fail 'partial findings were discarded'
            fi
            ;;
        validation_denied|enumeration_denied|policy_unready|missing_templates|missing_root)
            [ "$rc" -eq 0 ] || fail 'existing skip behavior changed'
            [ ! -e "$OUTPUT_DIR/nuclei-args" ] || fail 'scanner ran despite authorization/path gate'
            ! grep -q 'No takeover vulnerabilities detected' "$status_log" || fail 'skipped scan reported no findings'
            case "$case_name" in
                validation_denied) grep -q 'active validation was not authorized' "$status_log" || fail 'missing authorization skip' ;;
                missing_templates|missing_root) grep -q 'Takeover template directory missing' "$status_log" || fail 'missing template skip' ;;
                *) grep -q 'skipped by authorization policy' "$status_log" || fail 'missing policy skip' ;;
            esac
            ;;
        *)
            [ "$rc" -eq 0 ] || fail 'successful scan failed the phase'
            [ "$CHECKPOINT_FROZEN" = false ] || fail 'successful phase froze checkpoint advancement'
            [ "$(cat "$OUTPUT_DIR/checkpoint")" = 2 ] || fail 'successful phase did not advance checkpoint'
            [ "$(tail -n 1 "$OUTPUT_DIR/states")" = complete ] || fail 'successful phase status changed'
            grep -q 'Phase 2 complete!' "$status_log" || fail 'missing phase success'
            ! grep -q 'inconclusive' "$status_log" || fail 'successful scan reported inconclusive'
            if [ "$case_name" = findings ]; then
                grep -q 'Potential takeover vulnerabilities found' "$status_log" || fail 'missing finding status'
                ! grep -q 'No takeover vulnerabilities detected' "$status_log" || fail 'findings reported as empty'
            else
                grep -q 'No takeover vulnerabilities detected' "$status_log" || fail 'missing successful empty result'
            fi
            ;;
    esac

    if [ -f "$OUTPUT_DIR/nuclei-args" ]; then
        ! grep -Eq '^-severity$|^-s$' "$OUTPUT_DIR/nuclei-args" || fail 'takeover inherited severity filter'
        grep -Fxq -- "$NUCLEI_TEMPLATES/http/takeovers/" "$OUTPUT_DIR/nuclei-args" || fail 'takeover template path changed'
        [ "$(count_lines "$OUTPUT_DIR/selected-templates")" -eq 5 ] || fail 'not all takeover severities selected'
        cmp -s "$OUTPUT_DIR/nuclei-targets" "$OUTPUT_DIR/expected-targets" || fail 'exact target scope changed'
        grep -qx 'SEVERITY=' "$p2dir/takeover-findings.txt.templates.txt" || fail 'takeover identity has wrong severity'
    fi

    # Run ordinary scans after the Phase 2 call, including tagged and explicit
    # template selections, to catch a leaking override or a global policy change.
    if [ "$case_name" = empty ]; then
        local variant
        for variant in default tagged explicit; do
            local -a extra=()
            case "$variant" in
                tagged) extra=(-tags exposure,config,misconfig) ;;
                explicit) extra=(-t "$NUCLEI_TEMPLATES/http/takeovers/") ;;
            esac
            nuclei_target_scan list "$OUTPUT_DIR/phase1-subdomains/all-subdomains.txt" \
                -l @AUTHORIZED_INPUT@ -o "$OUTPUT_DIR/general.txt" "${extra[@]}" \
                > "$OUTPUT_DIR/general.log" 2>&1 || rc=$?
            if [ "$mode:$variant" = fast:explicit ]; then
                [ "$rc" -ne 0 ] || fail 'ordinary explicit scan lost Critical-only filtering'
                rc=0
            else
                [ "$rc" -eq 0 ] || fail 'ordinary scan failed'
            fi
            grep -qx -- '-severity' "$OUTPUT_DIR/nuclei-args" || fail 'ordinary scan lost severity flag'
            grep -Fxq -- "$expected_severity" "$OUTPUT_DIR/nuclei-args" || fail 'ordinary scan severity changed'
            grep -qx "SEVERITY=$expected_severity" "$OUTPUT_DIR/general.txt.templates.txt" || fail 'ordinary identity severity changed'
            local count="$expected_count"
            [ "$variant" != explicit ] || count=$((count - 1))
            [ "$(count_lines "$OUTPUT_DIR/selected-templates")" -eq "$count" ] || fail 'ordinary template selection changed'
        done
        # Exercise the wrapper's own path and output checks independently of Phase 2.
        if nuclei_target_scan list "$OUTPUT_DIR/expected-targets" -t "$OUTPUT_DIR/missing" -o "$OUTPUT_DIR/no.txt" \
            > "$OUTPUT_DIR/path-check.log" 2>&1; then
            fail 'wrapper accepted a missing selected template path'
        fi
        if nuclei_target_scan list "$OUTPUT_DIR/expected-targets" -l @AUTHORIZED_INPUT@ \
            > "$OUTPUT_DIR/output-check.log" 2>&1; then
            fail 'wrapper accepted a missing output path'
        fi
        NUCLEI_TEMPLATES="$OUTPUT_DIR/missing"
        if nuclei_target_scan list "$OUTPUT_DIR/expected-targets" -o "$OUTPUT_DIR/no.txt" \
            > "$OUTPUT_DIR/root-check.log" 2>&1; then
            fail 'wrapper accepted a missing template root'
        fi
    fi
    printf 'PASS: %s %s\n' "$mode" "$case_name"
)

for mode in fast normal deep; do
    for scenario in empty findings scan_failure partial_failure identity_failure \
        validation_denied enumeration_denied policy_unready missing_templates missing_root; do
        run_case "$mode" "$scenario" || exit 1
    done
done
