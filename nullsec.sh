#!/bin/bash
# Exit on unset variables; pipefail catches mid-pipeline failures.
# Note: 'set -e' is intentionally omitted — individual phase failures should
# be non-fatal so remaining phases can still run.
set -uo pipefail

# Recon output may contain credentials, tokens, private keys, and sensitive evidence.
# Restrict every file and directory created by this process to the current user.
umask 077

################################################################################
#                                                                              #
#      ███╗   ██╗ ██╗   ██╗ ██╗      ██╗      ███████╗ ███████╗  ██████╗       #
#      ████╗  ██║ ██║   ██║ ██║      ██║      ██╔════╝ ██╔════╝ ██╔════╝       #
#      ██╔██╗ ██║ ██║   ██║ ██║      ██║      ███████╗ █████╗   ██║            #
#      ██║╚██╗██║ ██║   ██║ ██║      ██║      ╚════██║ ██╔══╝   ██║            #
#      ██║ ╚████║ ╚██████╔╝ ███████╗ ███████╗ ███████║ ███████╗ ╚██████╗       #
#      ╚═╝  ╚═══╝  ╚═════╝  ╚══════╝ ╚══════╝ ╚══════╝ ╚══════╝  ╚═════╝       #
#                                                                              #
#            BUG BOUNTY RECONNAISSANCE AUTOMATION FRAMEWORK                    #
#                       Complete 12-Phase Methodology                          #
#                                                                              #
#                          Created by: Jonaski                                #
#                    Bug Bounty Researcher & Security Practitioner             #
#                                                                              #
################################################################################

#==============================================================================#
#                           CONFIGURATION SECTION                              #
#==============================================================================#

VERSION="1.0.2"
AUTHOR="Jonaski"

TARGET=""
OUTPUT_DIR=""

# Authorization is explicit, independent of scan mode, and loaded once per run.
# Policy files are operator inputs outside this three-file repository.
INCLUDE_SCOPE_FILE=""
EXCLUDE_SCOPE_FILE=""
CLOUD_APPROVAL_FILE=""
ALLOW_ACTIVE_ENUM=false
ALLOW_ACTIVE_VALIDATION=false
ALLOW_SECRET_VERIFICATION=false
POLICY_READY=false
INCLUDE_RULES=""
EXCLUDE_RULES=""
CLOUD_RULES=""
POLICY_FINGERPRINT=""

# Wordlist paths (modify to match your system)
WORDLIST_DIR="/usr/share/wordlists"
SECLISTS="$WORDLIST_DIR/seclists"
RESOLVERS="$WORDLIST_DIR/resolvers.txt"
DNS_WORDLIST="$SECLISTS/Discovery/DNS/subdomains-top1million-110000.txt"
PERM_WORDLIST="$SECLISTS/Discovery/DNS/subdomains-top1million-5000.txt"
WEB_WORDLIST="$SECLISTS/Discovery/Web-Content/raft-large-directories.txt"

# Thread / concurrency controls
HTTPX_THREADS=30
GAU_THREADS=5
ARJUN_THREADS=10
FFUF_THREADS=20
NUCLEI_RATE_LIMIT=50   # requests/second — lower if target is sensitive
NUCLEI_CONCURRENCY=25  # template/bulk-size workers — must stay ≤ NUCLEI_MHE (30)
GOWITNESS_THREADS=4

# Limits
MAX_JS_FILES=50         # max JS files to download in phase 8
MAX_JS_FILE_BYTES=5242880   # 5 MiB maximum per downloaded JavaScript response
MAX_JS_TOTAL_BYTES=52428800 # 50 MiB aggregate JavaScript download ceiling
MAX_ARJUN_HOSTS=5       # max hosts to run Arjun against
MAX_SCREENSHOTS=50      # max screenshots per category in phase 10
MAX_CORS_HOSTS=100      # max hosts to test CORS against
MAX_SCORE_HOSTS=200     # max hosts to score in asset scoring phase

# Cloud Storage Enumeration (Phase 2.5)
MAX_BUCKET_MUTATIONS=200    # max generated bucket name variants to test
CLOUD_ENUM_THREADS=20       # parallel curl checks
AWS_REGIONS=("us-east-1" "us-west-2" "eu-west-1" "ap-southeast-1")

# ── Phase 9 / 11 rate-control and wall-clock timeout settings ──────────────────
# Set by apply_scan_mode(); override manually after that call if needed.
#
# DALFOX_DELAY        ms between dalfox payloads (--delay). Floor: 50 ms on live
#                     targets — below that you risk WAF bans and program warnings.
# DALFOX_TIMEOUT      wall-clock seconds before `timeout` kills dalfox.  Prevents
#                     the 3-hour hang seen when feeding hundreds of XSS candidates
#                     at 300 ms each with no ceiling.
# XSS_CANDIDATE_CAP   Distinct injection points fed to dalfox (head -N AFTER
#                     dedup by host+path+param-keys).  Each unit is one real
#                     injection point, not a raw URL — much smaller than pre-dedup.
# DALFOX_WORKERS      dalfox concurrent workers (--worker).  Lower = gentler on
#                     the target / less likely to trip a WAF; higher = faster.
# SQLI_CANDIDATE_CAP  Distinct injection points fed to sqlmap per Phase 9 run.
# SQLMAP_TIMEOUT      wall-clock seconds before `timeout` kills sqlmap.
# FFUF_TIMEOUT        wall-clock seconds per ffuf host invocation in Phase 11.
# PHASE9_WALL_TIMEOUT hard ceiling (seconds) on the whole Phase 9 function;
#                     applied in main() around the background subshell.
# PHASE11_WALL_TIMEOUT hard ceiling (seconds) on the whole Phase 11 function.
DALFOX_DELAY=100
DALFOX_TIMEOUT=1800
DALFOX_WORKERS=10
XSS_CANDIDATE_CAP=500
SQLI_CANDIDATE_CAP=10
SQLMAP_TIMEOUT=1800
FFUF_TIMEOUT=300
PHASE8_WALL_TIMEOUT=3600
PHASE9_WALL_TIMEOUT=3600
PHASE10_WALL_TIMEOUT=3600
PHASE11_WALL_TIMEOUT=3600

# Nuclei templates path
# Leave empty by default so resolve_nuclei_templates() can prefer:
# 1) a valid NUCLEI_TEMPLATES environment variable,
# 2) $HOME/.local/nuclei-templates,
# 3) $HOME/nuclei-templates.
NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES:-}"

# Scan mode — set by --mode flag (fast | normal | deep)
# Can also be overridden by individual flags after apply_scan_mode() is called.
SCAN_MODE="normal"

# Flags
SKIP_TOOL_CHECK=false
UPDATE_NUCLEI=false     # use -u flag to enable nuclei template updates
RATE_LIMIT=false        # use -r flag to enable rate limiting between phases

# ── Telegram Notifications ─────────────────────────────────────────────────────
# Fill in your bot token and personal chat ID to receive real-time alerts.
# Leave both empty (default) to run silently with no notifications.
# Setup: message @BotFather → /newbot → copy token below.
#        Then message your bot once and run:
#          curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | jq '.result[0].message.chat.id'
#        to retrieve your chat ID.
#
# SECURITY: Never commit a real token to a public repo.  Prefer environment
# variables (export TELEGRAM_TOKEN=... in your shell or in a .env file that is
# gitignored) over hardcoding values here.  Anyone with the token can impersonate
# your bot and read prior chat history.  If you accidentally commit one, revoke
# it immediately via @BotFather → /revoke before pushing the fix.
TELEGRAM_TOKEN="${TELEGRAM_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

#==============================================================================#
#                         MODE-CONTROLLED SETTINGS                             #
# These are set automatically by apply_scan_mode() based on --mode.            #
# You can override any of them manually after that call if needed.             #
#==============================================================================#

# Phase enable/disable flags (all true by default; fast mode disables several)
RUN_DNS_BRUTEFORCE=true       # Phase 1: PureDNS wordlist bruteforce
RUN_PERMUTATIONS=true         # Phase 1: Gotator permutation generation
RUN_CLOUD_ENUM=true           # Phase 2.5: Cloud storage bucket enumeration
RUN_PORT_SCAN=true            # Phase 4: Naabu port scan
RUN_PARAM_DISCOVERY=true      # Phase 6: Arjun active parameter discovery
RUN_ASSET_SCORING=true         # Phase 6b: Score & rank assets by attack potential
RUN_JS_ANALYSIS=true          # Phase 8: JS download + TruffleHog + regex
RUN_PATTERN_HUNTING=true      # Phase 9: SSRF/XSS/SQLi/LFI/IDOR/CORS/HHI
RUN_SCREENSHOTS=true          # Phase 10: Gowitness screenshots
RUN_VHOST_DISCOVERY=true      # Phase 3: ffuf virtual-host Host-header fuzzing
RUN_FUZZING=true              # Phase 11: ffuf directory brute-force
RUN_ACTIVE_VULNS=true         # Phase 12: active vuln confirmation

# Nuclei severity filter (comma-separated; passed to nuclei -severity)
NUCLEI_SEVERITY="critical,high,medium"

# Katana crawl depth
KATANA_DEPTH=3

# Amass wall-clock timeout in seconds.
# Default normal-mode budget is 900s. Deep mode raises the default to 1800s.
# Override per run, for example:
#   NULLSEC_AMASS_TIMEOUT=1800 ./nullsec.sh -d example.com
# Prefer Amass v4.2.x because it streams the colored Open Asset Model graph:
#   host.example.com (FQDN) --> a_record --> 192.0.2.10 (IPAddress)
# Override these with environment variables when using a different binary name
# or configuration location. The maintained Amass binary remains a fallback.
AMASS_TIMEOUT="${NULLSEC_AMASS_TIMEOUT:-900}"
AMASS_PREFER_V4="${AMASS_PREFER_V4:-true}"
AMASS_V4_BIN="${AMASS_V4_BIN:-amass-v4}"
AMASS_V4_CONFIG="${AMASS_V4_CONFIG:-$HOME/.config/amass/config.yaml}"

#==============================================================================#
#                            UTILITY FUNCTIONS                                 #
#==============================================================================#

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# ── Interrupt / terminate cleanup ──────────────────────────────────────────────
# Ensures temp files and orphaned .bak files are removed when the user hits
# Ctrl+C or the process receives SIGTERM (e.g. from a scheduler).
#
# _PARALLEL_PIDS is populated by main() just before launching background phases.
# _ACTIVE_PIDS tracks long-running foreground wrappers (for example, timeout ->
# amass-v4) that are intentionally started asynchronously so the interrupt trap
# can terminate their complete process trees before the parent shell exits.
#
# The trap stops registered foreground and parallel jobs before merging .bak
# files. This prevents orphan scanners from continuing to write after Ctrl+C.
_PARALLEL_PIDS=()
_ACTIVE_PIDS=()
_CLEANUP_RUNNING=false

_register_active_pid() {
    local pid="${1:-}"
    [ -n "$pid" ] || return 1
    _ACTIVE_PIDS+=("$pid")
}

_unregister_active_pid() {
    local remove_pid="${1:-}" pid
    local -a kept=()
    [ -n "$remove_pid" ] || return 0

    for pid in "${_ACTIVE_PIDS[@]}"; do
        [ "$pid" = "$remove_pid" ] || kept+=("$pid")
    done
    _ACTIVE_PIDS=("${kept[@]}")
}

# Run a long-lived command in the background while preserving its stdout/stderr.
# The wrapper PID is registered globally so SIGINT/SIGTERM cleanup can kill the
# wrapper and every descendant. This keeps Amass v4's colored live graph output
# attached to the terminal while preventing orphan processes after Ctrl+C.
_run_tracked_command() {
    local pid rc

    "$@" &
    pid=$!
    _register_active_pid "$pid"

    wait "$pid"
    rc=$?

    _unregister_active_pid "$pid"
    return "$rc"
}

# Recursively signal descendants without killing their direct parent first.
# Keeping the wrapper alive briefly lets it reap terminated children instead of
# leaving zombies or abandoning grandchildren.
_signal_descendants() {
    local pid="$1" signal_name="${2:-TERM}" child
    [ -n "$pid" ] || return 0
    while IFS= read -r child; do
        [ -n "$child" ] || continue
        _signal_descendants "$child" "$signal_name"
        kill -s "$signal_name" "$child" 2>/dev/null || true
    done < <(pgrep -P "$pid" 2>/dev/null || true)
}

# Emit every descendant PID in post-order. Taking this snapshot before sending
# the first signal is critical: wrappers such as GNU timeout can exit quickly,
# causing still-running grandchildren to be re-parented and disappear from
# subsequent `pgrep -P <wrapper>` searches.
_collect_descendant_pids() {
    local pid="$1" child
    while IFS= read -r child; do
        [ -n "$child" ] || continue
        _collect_descendant_pids "$child"
        printf '%s\n' "$child"
    done < <(pgrep -P "$pid" 2>/dev/null || true)
}

# Terminate a process tree, allow programs to flush output, then force-kill any
# recorded member that outlives the bounded grace period.
#
# The optional third argument selects the first signal. Foreground scanners use
# INT so they can flush databases/output cleanly; watchdog and parallel cleanup
# use TERM. Every PID captured before signaling is independently escalated even
# when its original parent exits and the process becomes re-parented.
_terminate_process_tree() {
    local pid="$1" grace="${2:-5}" initial_signal="${3:-TERM}"
    local member deadline any_alive=false
    local -a process_tree=()

    [ -n "$pid" ] || return 0

    mapfile -t process_tree < <(_collect_descendant_pids "$pid")
    process_tree+=("$pid")

    for member in "${process_tree[@]}"; do
        kill -s "$initial_signal" "$member" 2>/dev/null || true
    done

    deadline=$(( $(date +%s) + grace ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        any_alive=false
        for member in "${process_tree[@]}"; do
            if kill -0 "$member" 2>/dev/null; then
                any_alive=true
                break
            fi
        done
        [ "$any_alive" = false ] && break
        sleep 0.1
    done

    for member in "${process_tree[@]}"; do
        if kill -0 "$member" 2>/dev/null; then
            kill -TERM "$member" 2>/dev/null || true
        fi
    done

    deadline=$(( $(date +%s) + grace ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        any_alive=false
        for member in "${process_tree[@]}"; do
            if kill -0 "$member" 2>/dev/null; then
                any_alive=true
                break
            fi
        done
        [ "$any_alive" = false ] && break
        sleep 0.1
    done

    for member in "${process_tree[@]}"; do
        if kill -0 "$member" 2>/dev/null; then
            kill -KILL "$member" 2>/dev/null || true
        fi
    done

    wait "$pid" 2>/dev/null || true
}

_nullsec_cleanup() {
    [ "$_CLEANUP_RUNNING" = true ] && exit 130
    _CLEANUP_RUNNING=true
    trap - SIGINT SIGTERM

    echo ""
    warn "Scan interrupted — terminating child processes and preserving output..."

    local _cpid
    if [ ${#_ACTIVE_PIDS[@]} -gt 0 ]; then
        for _cpid in "${_ACTIVE_PIDS[@]}"; do
            _terminate_process_tree "$_cpid" 7 INT
        done
        _ACTIVE_PIDS=()
    fi

    if [ ${#_PARALLEL_PIDS[@]} -gt 0 ]; then
        for _cpid in "${_PARALLEL_PIDS[@]}"; do
            _terminate_process_tree "$_cpid" 5 TERM
        done
        _PARALLEL_PIDS=()
    fi

    # Final safety sweep for any direct child that started between registration
    # and signal delivery. This is scoped to this NullSec shell only; it does not
    # use broad pkill patterns that could terminate unrelated user processes.
    local -a _leftover_children=()
    mapfile -t _leftover_children < <(pgrep -P "$$" 2>/dev/null || true)
    for _cpid in "${_leftover_children[@]}"; do
        _terminate_process_tree "$_cpid" 3 TERM
    done

    if [ -n "${OUTPUT_DIR:-}" ]; then
        rm -f "${OUTPUT_DIR}/phase7-vulns/.combined-targets.txt" \
              "${OUTPUT_DIR}/phase7-vulns/.host-targets.txt" \
              "${OUTPUT_DIR}/phase2.5-cloud/.tokens.txt" \
              "${OUTPUT_DIR}/phase2.5-cloud/.candidates.txt" \
              "${OUTPUT_DIR}/phase5-urls/.urls-scoped.txt" \
              "${OUTPUT_DIR}/phase5-urls/.urls-collapsed.txt" \
              "${OUTPUT_DIR}"/.parallel-start.* 2>/dev/null
        rm -rf "${OUTPUT_DIR}/asset-scoring/.tmp" \
               "${OUTPUT_DIR}/asset-scoring/.host-universe.txt" 2>/dev/null

        finalize_all_output_backups true 2>/dev/null || true
    fi

    warn "Cleanup complete. Re-run with -c '$OUTPUT_DIR' to resume from the last checkpoint."
    exit 130
}
trap _nullsec_cleanup SIGINT SIGTERM

print_banner() {
    # Avoid noisy "TERM environment variable not set" messages in non-interactive runs.
    if command -v clear >/dev/null 2>&1 && [ -t 1 ] && [ -n "${TERM:-}" ]; then
        clear
    fi

    _banner_center() {
        local text="$1"
        local width=78
        local text_len=${#text}
        local left=$(( (width - text_len) / 2 ))
        local right=$(( width - text_len - left ))
        printf '║%*s%s%*s║\n' "$left" "" "$text" "$right" ""
    }

    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                              ║"
    echo "║      ███╗   ██╗ ██╗   ██╗ ██╗      ██╗      ███████╗ ███████╗  ██████╗       ║"
    echo "║      ████╗  ██║ ██║   ██║ ██║      ██║      ██╔════╝ ██╔════╝ ██╔════╝       ║"
    echo "║      ██╔██╗ ██║ ██║   ██║ ██║      ██║      ███████╗ █████╗   ██║            ║"
    echo "║      ██║╚██╗██║ ██║   ██║ ██║      ██║      ╚════██║ ██╔══╝   ██║            ║"
    echo "║      ██║ ╚████║ ╚██████╔╝ ███████╗ ███████╗ ███████║ ███████╗ ╚██████╗       ║"
    echo "║      ╚═╝  ╚═══╝  ╚═════╝  ╚══════╝ ╚══════╝ ╚══════╝ ╚══════╝  ╚═════╝       ║"
    echo "║                                                                              ║"
    _banner_center "NullSec Framework v${VERSION}"
    _banner_center "Complete 12-Phase Methodology"
    echo "║                                                                              ║"
    _banner_center "Created by ${AUTHOR}"
    _banner_center "Bug Bounty Hunter & Security Researcher"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""

    unset -f _banner_center
}

print_phase() {
    echo ""
    echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC} ${YELLOW}$1${NC}"
    echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

info()    { echo -e "${BLUE}[$(date +%H:%M)][INFO]${NC} $1"; }
success() { echo -e "${GREEN}[$(date +%H:%M)][SUCCESS]${NC} $1"; }
warn()    { echo -e "${YELLOW}[$(date +%H:%M)][WARNING]${NC} $1"; }
error()   { echo -e "${RED}[$(date +%H:%M)][ERROR]${NC} $1"; }

check_command() {
    command -v "$1" &>/dev/null
}

# Safe line count — handles missing or empty files gracefully
count_lines() {
    local file="$1"
    if [ -f "$file" ]; then
        wc -l < "$file"
    else
        echo "0"
    fi
}

check_readable_file() {
    local file="$1" label="${2:-$1}"
    if [ -s "$file" ] && [ -r "$file" ]; then
        echo -e "  ${GREEN}✓${NC} $label"
        return 0
    fi
    echo -e "  ${YELLOW}○${NC} $label (missing, empty, or unreadable — related phase may be skipped/reduced)"
    return 1
}

resolve_nuclei_templates() {
    local announce="${1:-true}"
    local configured="${NUCLEI_TEMPLATES:-}"
    local candidate resolved

    if [ -n "$configured" ]; then
        if [ -d "$configured" ]; then
            resolved=$(cd "$configured" 2>/dev/null && pwd -P)
            NUCLEI_TEMPLATES="$resolved"
            [ "$announce" = true ] && success "Using Nuclei templates directory: $NUCLEI_TEMPLATES"
            return 0
        fi
        [ "$announce" = true ] && warn "NUCLEI_TEMPLATES is set but not a valid directory: $configured"
    fi

    for candidate in "$HOME/.local/nuclei-templates" "$HOME/nuclei-templates"; do
        if [ -d "$candidate" ]; then
            resolved=$(cd "$candidate" 2>/dev/null && pwd -P)
            NUCLEI_TEMPLATES="$resolved"
            [ "$announce" = true ] && success "Using Nuclei templates directory: $NUCLEI_TEMPLATES"
            return 0
        fi
    done

    NUCLEI_TEMPLATES="$HOME/.local/nuclei-templates"
    if [ "$announce" = true ]; then
        warn "Nuclei templates directory not found. Run: nuclei -ut"
        warn 'Or set: export NUCLEI_TEMPLATES="$HOME/.local/nuclei-templates"'
    fi
    return 1
}

# Host rules are exact names or *.domain (subdomains only, not the apex).
# Exclusions override inclusions. Filtering requires a loaded current policy.
_trim_policy_line() {
    local line="${1%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    printf '%s\n' "$line"
}

_valid_policy_host() {
    local host="$1"
    [ "${#host}" -le 253 ] &&
        [[ "$host" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] &&
        [[ "${host##*.}" =~ ^[a-z] ]] &&
        ! [[ "$host" =~ ^[0-9.]+$ ]]
}

# Strict HTTP(S)/DNS authority parsing. Userinfo, IPs, wildcard authorities,
# backslashes, escaped authorities and ambiguous ports are rejected.
# Paths/query values retain case; hostnames and schemes are canonicalized.
normalize_scope_input() {
    local line="$1" scheme="" rest authority host port="" tail=""
    [[ -n "$line" && "$line" != *[[:space:][:cntrl:]]* && "$line" != *\\* ]] || return 1
    if [[ "$line" == *://* ]]; then
        scheme="${line%%://*}"; scheme="${scheme,,}"
        [[ "$scheme" == http || "$scheme" == https ]] || return 1
        rest="${line#*://}"
        authority="${rest%%[/?#]*}"
        tail="${rest#"$authority"}"
    else
        [[ "$line" != *[/?#]* ]] || return 1
        authority="$line"
    fi
    [[ -n "$authority" && "$authority" != *[@%\[\]]* ]] || return 1
    host="$authority"
    if [[ "$authority" == *:* ]]; then
        host="${authority%:*}"; port="${authority##*:}"
        [[ "$host" != *:* && "$port" =~ ^[0-9]{1,5}$ ]] || return 1
        port=$((10#$port))
        [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 1
    fi
    host="${host,,}"; host="${host%.}"
    _valid_policy_host "$host" || return 1
    printf '%s%s%s%s\n' "${scheme:+$scheme://}" "$host" "${port:+:$port}" "$tail"
}

_host_rule_matches() {
    local host="$1" rule="$2"
    if [[ "$rule" == \*.* ]]; then
        [[ "$host" == *."${rule#*.}" ]]
    else
        [ "$host" = "$rule" ]
    fi
}

scope_host_excluded() {
    local host="$1" rule
    while IFS= read -r rule; do
        [ -n "$rule" ] || continue
        _host_rule_matches "$host" "$rule" && return 0
    done <<< "$EXCLUDE_RULES"
    return 1
}

scope_host_allowed() {
    local host="$1" rule included=false
    [ "$POLICY_READY" = true ] && [ -n "$INCLUDE_RULES" ] || return 1
    scope_host_excluded "$host" && return 1
    while IFS= read -r rule; do
        [ -n "$rule" ] || continue
        _host_rule_matches "$host" "$rule" && included=true
    done <<< "$INCLUDE_RULES"
    [ "$included" = true ]
}

in_scope() {
    local line normalized authority host
    [ "$POLICY_READY" = true ] && [ -n "$INCLUDE_RULES" ] || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        normalized=$(normalize_scope_input "$line") || continue
        authority="${normalized#*://}"; authority="${authority%%[/?#]*}"
        host="${authority%%:*}"
        scope_host_allowed "$host" || continue
        printf '%s\n' "$normalized" || return 1
    done
}

normalize_cloud_identity() {
    local identity="${1,,}" provider name
    [[ "$identity" == *:* ]] || return 1
    provider="${identity%%:*}"; name="${identity#*:}"
    case "$provider" in
        s3) [[ "$name" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ && "$name" != *..* ]] || return 1 ;;
        gcs) [[ "$name" =~ ^[a-z0-9][a-z0-9._-]*[a-z0-9]$ && "$name" != *..* ]] || return 1 ;;
        azure) [[ "$name" =~ ^[a-z0-9]+$ && "${#name}" -le 24 ]] || return 1 ;;
        *) return 1 ;;
    esac
    [ "${#name}" -ge 3 ] && [ "${#name}" -le 63 ] || return 1
    printf '%s:%s\n' "$provider" "$name"
}

_read_policy_rules() {
    local file="$1" kind="$2" line rule base
    [ -f "$file" ] && [ -r "$file" ] || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        line=$(_trim_policy_line "${line%%#*}") || return 1
        [ -n "$line" ] || continue
        if [ "$kind" = cloud ]; then
            rule=$(normalize_cloud_identity "$line") || return 1
        else
            rule="${line,,}"; rule="${rule%.}"; base="${rule#\*.}"
            _valid_policy_host "$base" || return 1
            [[ "$rule" == "$base" || "$rule" == "*.$base" ]] || return 1
        fi
        printf '%s\n' "$rule" || return 1
    done < "$file"
}

load_authorization_policy() {
    POLICY_READY=false
    if [ -n "$INCLUDE_SCOPE_FILE" ]; then
        INCLUDE_RULES=$(_read_policy_rules "$INCLUDE_SCOPE_FILE" hosts | LC_ALL=C sort -u) || return 1
    else
        INCLUDE_RULES="${TARGET,,}"; INCLUDE_RULES="${INCLUDE_RULES%.}"
        _valid_policy_host "$INCLUDE_RULES" || return 1
    fi
    [ -n "$INCLUDE_RULES" ] || return 1
    EXCLUDE_RULES=""; CLOUD_RULES=""
    if [ -n "$EXCLUDE_SCOPE_FILE" ]; then
        EXCLUDE_RULES=$(_read_policy_rules "$EXCLUDE_SCOPE_FILE" hosts | LC_ALL=C sort -u) || return 1
    fi
    if [ -n "$CLOUD_APPROVAL_FILE" ]; then
        CLOUD_RULES=$(_read_policy_rules "$CLOUD_APPROVAL_FILE" cloud | LC_ALL=C sort -u) || return 1
    fi
    case "$ALLOW_ACTIVE_ENUM:$ALLOW_ACTIVE_VALIDATION:$ALLOW_SECRET_VERIFICATION" in
        true:true:true|true:true:false|true:false:true|true:false:false|false:true:true|false:true:false|false:false:true|false:false:false) ;;
        *) return 1 ;;
    esac
    POLICY_FINGERPRINT=$(
        printf 'POLICY_VERSION=1\nTARGET=%s\nENUM=%s\nVALIDATE=%s\nVERIFY=%s\nINCLUDE\n%s\nEXCLUDE\n%s\nCLOUD\n%s\n' \
            "$TARGET" "$ALLOW_ACTIVE_ENUM" "$ALLOW_ACTIVE_VALIDATION" "$ALLOW_SECRET_VERIFICATION" \
            "$INCLUDE_RULES" "$EXCLUDE_RULES" "$CLOUD_RULES" | sha256sum
    ) || return 1
    POLICY_FINGERPRINT="${POLICY_FINGERPRINT%% *}"
    [[ "$POLICY_FINGERPRINT" =~ ^[0-9a-f]{64}$ ]] || return 1
    POLICY_READY=true
    export POLICY_READY INCLUDE_RULES EXCLUDE_RULES CLOUD_RULES POLICY_FINGERPRINT
    export ALLOW_ACTIVE_ENUM ALLOW_ACTIVE_VALIDATION ALLOW_SECRET_VERIFICATION
}

authorization_allowed() {
    [ "$POLICY_READY" = true ] || return 1
    case "$1" in
        passive) return 0 ;;
        enumeration) [ "$ALLOW_ACTIVE_ENUM" = true ] ;;
        validation) [ "$ALLOW_ACTIVE_ENUM" = true ] && [ "$ALLOW_ACTIVE_VALIDATION" = true ] ;;
        verification) [ "$ALLOW_SECRET_VERIFICATION" = true ] ;;
        *) return 1 ;;
    esac
}

cloud_resource_allowed() {
    local identity rule provider name host
    authorization_allowed enumeration || return 1
    identity=$(normalize_cloud_identity "$1") || return 1
    provider="${identity%%:*}"; name="${identity#*:}"
    case "$provider" in
        s3) host="$name.s3.amazonaws.com" ;;
        gcs) host=storage.googleapis.com ;;
        azure) host="$name.blob.core.windows.net" ;;
    esac
    scope_host_excluded "$host" && return 1
    while IFS= read -r rule; do
        [ "$identity" = "$rule" ] && return 0
    done <<< "$CLOUD_RULES"
    return 1
}

cloud_approved_names() {
    local provider="$1" name
    [ "$POLICY_READY" = true ] || return 1
    while IFS= read -r name || [ -n "$name" ]; do
        cloud_resource_allowed "$provider:$name" || continue
        printf '%s\n' "$name" || return 1
    done
}

validate_resume_authorization() {
    local file="$1" stored
    [ "$POLICY_READY" = true ] && [ -r "$file" ] || return 1
    stored=$(awk -F= '$1=="POLICY_FINGERPRINT" {n++; if(NF!=2) invalid=1; value=$2} END {if(n!=1 || invalid) exit 1; print value}' "$file") || return 1
    [[ "$stored" =~ ^[0-9a-f]{64}$ ]] && [ "$stored" = "$POLICY_FINGERPRINT" ]
}

# Every controlled target launch uses a newly filtered snapshot or scalar.
# @AUTHORIZED_INPUT@ is replaced only after successful authorization. This
# controls seed inputs, not requests generated internally by external tools.
authorized_run() (
    local action="$1" kind="$2" input="$3" prepared="" tmp="" arg host label
    shift 3
    [ "$POLICY_READY" = true ] || return 1
    if ! authorization_allowed "$action"; then
        printf 'Authorization: skipped %s action\n' "$action" >&2
        return 0
    fi
    trap '[ -z "$tmp" ] || rm -f -- "$tmp"' EXIT
    case "$kind" in
        host)
            prepared=$(printf '%s\n' "$input" | in_scope) || return 1
            [ -n "$prepared" ] || return 0 ;;
        list|stream|dns-wordlist)
            tmp=$(mktemp "${TMPDIR:-/tmp}/nullsec-authorized.XXXXXX") || return 1
            if [ "$kind" = stream ]; then
                in_scope > "$tmp" || return 1
            elif [ "$kind" = list ]; then
                in_scope < "$input" > "$tmp" || return 1
            else
                # Filter generated DNS destinations before handing labels to
                # the brute-force tool; exclusions apply after expansion.
                while IFS= read -r label || [ -n "$label" ]; do
                    host="$label.$TARGET"
                    prepared=$(printf '%s\n' "$host" | in_scope) || return 1
                    [ -z "$prepared" ] || printf '%s\n' "$label" || return 1
                done < "$input" > "$tmp" || return 1
            fi
            [ -s "$tmp" ] || return 0
            prepared="$tmp" ;;
        service)
            [ "$action" = passive ] || return 1
            case "$input" in
                "https://crt.sh/?q=%25.$TARGET&output=json") scope_host_allowed "$TARGET" || return 0 ;;
                https://1.1.1.1/cdn-cgi/trace|telegram) ;;
                *) return 1 ;;
            esac
            prepared="$input" ;;
        maintenance) [ "$action" = validation ] || return 1; prepared="$input" ;;
        local-verification) [ "$action" = verification ] || return 1; prepared="$input" ;;
        *) return 1 ;;
    esac
    local -a args=()
    for arg in "$@"; do
        case "$arg" in
            -follow-redirects|-follow-host-redirects|-fr|-fhr|--location*|-L) return 1 ;;
        esac
        if [[ "$arg" == -?* && "$arg" != --* && "$arg" == *L* ]]; then return 1; fi
        if [ "$arg" = '@AUTHORIZED_INPUT@' ]; then arg="$prepared"; fi
        args+=("$arg")
    done
    if [ "$kind" = stream ]; then
        "${args[@]}" < "$tmp"
    else
        "${args[@]}"
    fi
)

# Each worker request independently checks the exact provider identity.
# Curl config defaults and redirects are disabled for controlled downloads.
authorized_cloud_curl() {
    local identity="$1" provider name arg found_url=false
    shift
    cloud_resource_allowed "$identity" || return 0
    identity=$(normalize_cloud_identity "$identity") || return 1
    provider="${identity%%:*}"; name="${identity#*:}"
    for arg in "$@"; do
        case "$arg" in --location*|-L|--config|-K) return 1 ;; esac
        if [[ "$arg" == -?* && "$arg" != --* && "$arg" == *L* ]]; then return 1; fi
        if [[ "$arg" == http://* || "$arg" == https://* ]]; then
            found_url=true
            case "$provider:$arg" in
                "s3:https://$name.s3.amazonaws.com"|"s3:https://$name.s3.amazonaws.com?acl"|"s3:https://$name.s3.amazonaws.com?policy") ;;
                "gcs:https://storage.googleapis.com/$name"|"gcs:https://storage.googleapis.com/storage/v1/b/$name"|"gcs:https://storage.googleapis.com/storage/v1/b/$name/o?maxResults=10"|"gcs:https://storage.googleapis.com/storage/v1/b/$name/iam") ;;
                "azure:https://$name.blob.core.windows.net"|"azure:https://$name.blob.core.windows.net/"*) ;;
                *) return 1 ;;
            esac
        fi
    done
    [ "$found_url" = true ] || return 1
    command curl -q --proto '=https' --max-redirs 0 "$@"
}
export -f _valid_policy_host normalize_scope_input _host_rule_matches scope_host_excluded scope_host_allowed in_scope
export -f normalize_cloud_identity authorization_allowed cloud_resource_allowed authorized_cloud_curl

apply_authorization_controls() {
    # Modes may reduce permissions; they never grant them.
    if ! authorization_allowed enumeration; then
        RUN_DNS_BRUTEFORCE=false
        RUN_PERMUTATIONS=false
        RUN_CLOUD_ENUM=false
        RUN_PORT_SCAN=false
        RUN_PARAM_DISCOVERY=false
        RUN_ASSET_SCORING=false
        RUN_JS_ANALYSIS=false
        RUN_PATTERN_HUNTING=false
        RUN_SCREENSHOTS=false
        RUN_FUZZING=false
        RUN_ACTIVE_VULNS=false
    fi
    if ! authorization_allowed validation; then
        RUN_PARAM_DISCOVERY=false
        RUN_FUZZING=false
        RUN_ACTIVE_VULNS=false
    fi
    [ -n "$CLOUD_RULES" ] || RUN_CLOUD_ENUM=false
    # The existing vhost implementation converts authorized hostnames to direct
    # IP seeds. This host-only policy cannot approve that transformed authority.
    RUN_VHOST_DISCOVERY=false
}

# Optional sleep between phases when -r flag is used
polite_sleep() {
    if [ "$RATE_LIMIT" = true ]; then
        info "Rate-limit mode: sleeping 10s before next phase..."
        sleep 10
    fi
}

# ── Telegram notification helper ───────────────────────────────────────────────
# Sends a message to your Telegram bot.  Silently no-ops if TELEGRAM_TOKEN or
# TELEGRAM_CHAT_ID are empty, so it is always safe to call.
#
# Usage: notify "<severity_label>" "<message body>"
# Examples:
#   notify "🔥 CRITICAL" "3 writable S3 buckets found"
#   notify "✅ Done" "All 12 phases finished in 42m 17s"
#
# Messages are sent in Markdown format.  Asterisks and backticks are safe to
# use in the severity label and message body.
notify() {
    [ -z "${TELEGRAM_TOKEN:-}" ] || [ -z "${TELEGRAM_CHAT_ID:-}" ] && return 0
    [[ "$TELEGRAM_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ && "$TELEGRAM_CHAT_ID" =~ ^-?[0-9]+$ ]] || return 1
    local label="$1" body="$2" text cfg
    text=$(printf '*[NullSec]* %s
`Target:` %s
`Time:  ` %s

%s' \
        "$label" "$TARGET" "$(date '+%Y-%m-%d %H:%M')" "$body")
    cfg=$(mktemp)
    chmod 600 "$cfg"
    printf 'url = "https://api.telegram.org/bot%s/sendMessage"
' "$TELEGRAM_TOKEN" > "$cfg"
    authorized_run passive service telegram curl -q --proto '=https' --max-redirs 0 -s -X POST --config "$cfg" \
        --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
        --data-urlencode "text=${text}" \
        --data-urlencode "parse_mode=Markdown" \
        -o /dev/null || true
    rm -f "$cfg"
}

CHECKPOINT_FILE=""
RESUME_FROM=0
SCAN_META_FILE=""
CHECKPOINT_FROZEN=false

save_checkpoint() {
    local phase_num="$1" tmp
    if [ "$CHECKPOINT_FROZEN" = true ]; then
        return 0
    fi
    if [ -n "$CHECKPOINT_FILE" ]; then
        tmp="${CHECKPOINT_FILE}.tmp.$$"
        printf '%s\n' "$phase_num" > "$tmp"
        mv -f "$tmp" "$CHECKPOINT_FILE"
        RESUME_FROM="$phase_num"
    fi
}

phase_done() {
    local phase_num="$1"
    local resume_int="${RESUME_FROM%.*}"
    if [ "${resume_int:-0}" -ge "$phase_num" ]; then
        info "Phase $phase_num already completed — skipping (checkpoint)."
        return 0
    fi
    return 1
}

safe_artifact_name() {
    local value="$1" readable digest
    readable=$(printf '%s' "$value" | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#[^a-zA-Z0-9._-]+#_#g; s#^_+|_+$##g' | cut -c1-80)
    digest=$(printf '%s' "$value" | sha256sum | awk '{print substr($1,1,16)}')
    printf '%s-%s\n' "${readable:-target}" "$digest"
}

# Snapshot every regular file recursively. Fresh results remain authoritative;
# previous evidence is archived under prior-runs instead of being overwritten.
backup_phase_outputs() {
    local phase_dir="$1" phase_key stamp backup_dir file rel copied=0 root
    [ -d "$phase_dir" ] || return 0
    phase_key=$(basename "$phase_dir")
    root="$OUTPUT_DIR/.phase-backups/$phase_key"

    # A resume-wide snapshot may already protect this phase. Avoid duplicate
    # snapshots when the phase itself calls this helper again.
    if [ -d "$root" ] && find "$root" -type f -name .active -print -quit 2>/dev/null | grep -q .; then
        return 0
    fi

    stamp="$(date +%Y%m%d-%H%M%S)-${BASHPID}"
    backup_dir="$root/$stamp"

    while IFS= read -r -d '' file; do
        rel="${file#"$phase_dir"/}"
        mkdir -p "$backup_dir/$(dirname "$rel")"
        cp -p "$file" "$backup_dir/$rel"
        copied=$(( copied + 1 ))
    done < <(find "$phase_dir" -type f \
        ! -path "$phase_dir/prior-runs/*" \
        ! -name '*.bak' -print0 2>/dev/null)

    if [ "$copied" -gt 0 ]; then
        : > "$backup_dir/.active"
        info "  Preserved $copied existing output file(s) from $phase_key"
    else
        rm -rf "$backup_dir"
    fi
}

merge_phase_backup() {
    local phase_dir="$1" restore_missing="${2:-false}"
    local phase_key root backup_dir stamp file rel current archive
    [ -d "$phase_dir" ] || return 0
    phase_key=$(basename "$phase_dir")
    root="$OUTPUT_DIR/.phase-backups/$phase_key"

    if [ -d "$root" ]; then
        for backup_dir in "$root"/*; do
            [ -d "$backup_dir" ] && [ -f "$backup_dir/.active" ] || continue
            stamp=$(basename "$backup_dir")
            archive="$phase_dir/prior-runs/$stamp"
            while IFS= read -r -d '' file; do
                [ "$(basename "$file")" = ".active" ] && continue
                rel="${file#"$backup_dir"/}"
                current="$phase_dir/$rel"
                if [ "$restore_missing" = true ] && [ ! -s "$current" ]; then
                    # Interruption path: restore evidence that a killed phase did
                    # not replace. Successful reruns never repopulate current
                    # results with stale findings.
                    mkdir -p "$(dirname "$current")"
                    cp -p "$file" "$current"
                else
                    mkdir -p "$archive/$(dirname "$rel")"
                    cp -p "$file" "$archive/$rel"
                fi
            done < <(find "$backup_dir" -type f -print0)
            rm -rf "$backup_dir"
        done
        rmdir "$root" 2>/dev/null || true
    fi

    # Recover legacy sibling .bak files created by older NullSec versions.
    while IFS= read -r -d '' file; do
        current="${file%.bak}"
        if [ "$restore_missing" = true ] && [ ! -s "$current" ]; then
            mv -f "$file" "$current"
        else
            mkdir -p "$phase_dir/prior-runs/legacy"
            rel="${file#"$phase_dir"/}"
            mkdir -p "$phase_dir/prior-runs/legacy/$(dirname "$rel")"
            mv -f "$file" "$phase_dir/prior-runs/legacy/$rel"
        fi
    done < <(find "$phase_dir" -type f -name '*.bak' -print0 2>/dev/null)
}

_all_output_dirs() {
    printf '%s\n' \
        "$OUTPUT_DIR/phase1-subdomains" \
        "$OUTPUT_DIR/phase2-validation" \
        "$OUTPUT_DIR/phase2.5-cloud" \
        "$OUTPUT_DIR/phase3-probing" \
        "$OUTPUT_DIR/phase4-portscan" \
        "$OUTPUT_DIR/phase5-urls" \
        "$OUTPUT_DIR/phase6-parameters" \
        "$OUTPUT_DIR/asset-scoring" \
        "$OUTPUT_DIR/phase7-vulns" \
        "$OUTPUT_DIR/phase8-javascript" \
        "$OUTPUT_DIR/phase9-patterns" \
        "$OUTPUT_DIR/phase10-screenshots" \
        "$OUTPUT_DIR/phase11-fuzzing" \
        "$OUTPUT_DIR/phase12-active-vulns" \
        "$OUTPUT_DIR/reports"
}

snapshot_all_outputs() {
    local phase_dir
    while IFS= read -r phase_dir; do
        backup_phase_outputs "$phase_dir"
    done < <(_all_output_dirs)
}

finalize_all_output_backups() {
    local restore_missing="${1:-false}" phase_dir
    while IFS= read -r phase_dir; do
        merge_phase_backup "$phase_dir" "$restore_missing"
    done < <(_all_output_dirs)
}

#==============================================================================#
#                           SCAN MODE PRESETS                                  #
#==============================================================================#

apply_scan_mode() {
    case "$SCAN_MODE" in

        # ── FAST ─────────────────────────────────────────────────────────────
        # Passive subdomain sources only, critical-only Nuclei, no heavy active
        # steps. Good for hourly scheduled runs. Typical runtime: 5–15 min.
        fast)
            info "Scan mode: FAST — passive sources, critical vulns, no bruteforce/fuzzing"

            # Phase 1 — passive only; skip bruteforce and permutations
            RUN_DNS_BRUTEFORCE=false
            RUN_PERMUTATIONS=false

            # Phase 2.5 — skip cloud enum (passive only in fast mode)
            RUN_CLOUD_ENUM=false

            # Phase 4 — skip port scan
            RUN_PORT_SCAN=false

            # Phase 6 — skip active parameter discovery (Arjun is slow)
            RUN_PARAM_DISCOVERY=false

            # Phase 8 — skip JS download and secret extraction
            RUN_JS_ANALYSIS=false

            # Asset scoring — skip (not enough data in fast mode)
            RUN_ASSET_SCORING=false

            # Phase 9 — skip pattern hunting (no URLs from crawl anyway)
            RUN_PATTERN_HUNTING=false

            # Phase 10 — skip screenshots
            RUN_SCREENSHOTS=false

            # Phase 11 — skip directory fuzzing
            RUN_FUZZING=false

            # Phase 3 vhost discovery — skip (requires ffuf; fast mode avoids active steps)
            RUN_VHOST_DISCOVERY=false

            # Phase 12 — skip active confirmation
            RUN_ACTIVE_VULNS=false

            # Nuclei — critical severity only
            NUCLEI_SEVERITY="critical"

            # Katana — shallower crawl
            KATANA_DEPTH=1

            # Amass — configurable timeout; fast mode keeps a shorter default.
            AMASS_TIMEOUT="${NULLSEC_AMASS_TIMEOUT:-300}"

            # Concurrency — lower threads since we're running more often
            HTTPX_THREADS=15
            NUCLEI_RATE_LIMIT=30
            NUCLEI_CONCURRENCY=15  # well below MHE default (30); fast mode is gentle

            # Phase 9 / 11 timing — fast mode skips both phases entirely, but
            # set conservative floors in case flags are overridden manually.
            # NOTE: candidate caps now bound DISTINCT INJECTION POINTS (dedup by
            # host+path+param-keys runs BEFORE the cap), not raw URLs — so these
            # numbers are far smaller than pre-dedup and each unit is real work.
            # DALFOX_DELAY floor is 50 ms; never set lower on live targets.
            DALFOX_DELAY=50
            DALFOX_TIMEOUT=600          # 10 min hard cap
            DALFOX_WORKERS=15           # higher concurrency; fast mode prioritises speed
            XSS_CANDIDATE_CAP=25        # distinct injection points
            SQLI_CANDIDATE_CAP=5
            SQLMAP_TIMEOUT=300          # 5 min
            FFUF_TIMEOUT=120            # 2 min per host
            PHASE8_WALL_TIMEOUT=900
            PHASE9_WALL_TIMEOUT=900     # 15 min absolute ceiling
            PHASE10_WALL_TIMEOUT=900
            PHASE11_WALL_TIMEOUT=900
            ;;

        # ── NORMAL ───────────────────────────────────────────────────────────
        # Adds DNS bruteforce, full crawling, JS analysis, and pattern hunting.
        # Skips the most expensive active steps. Good for daily runs.
        # Typical runtime: 30–60 min.
        normal)
            info "Scan mode: NORMAL — full discovery + JS analysis, no fuzzing/active confirm"

            RUN_DNS_BRUTEFORCE=true
            RUN_PERMUTATIONS=false      # permutations are expensive; deep only
            RUN_CLOUD_ENUM=true         # cloud enum runs in normal + deep
            RUN_PORT_SCAN=true
            RUN_PARAM_DISCOVERY=false   # Arjun is slow; skip for daily cadence
            RUN_ASSET_SCORING=true      # Score & rank targets for focused effort
            RUN_JS_ANALYSIS=true
            RUN_PATTERN_HUNTING=true
            RUN_SCREENSHOTS=true
            RUN_VHOST_DISCOVERY=true    # vhost discovery enabled in normal + deep
            RUN_FUZZING=false           # ffuf recursive fuzzing; deep only
            RUN_ACTIVE_VULNS=false      # active confirmation; deep only

            NUCLEI_SEVERITY="critical,high,medium"
            KATANA_DEPTH=2
            AMASS_TIMEOUT="${NULLSEC_AMASS_TIMEOUT:-900}"

            HTTPX_THREADS=30
            NUCLEI_RATE_LIMIT=50
            NUCLEI_CONCURRENCY=25  # balanced; stays under MHE default (30)

            # Phase 9 / 11 timing — normal mode runs both phases.
            # Caps bound DISTINCT INJECTION POINTS (post-dedup), so these are much
            # smaller than the old raw-URL caps and each unit is genuine testing.
            # The timeout is a SAFETY NET for true hangs, not a per-run guillotine:
            # 100 distinct points × dalfox's internal payload set at 100 ms,
            # parallelised across DALFOX_WORKERS, completes well inside 30 min on a
            # responsive target. If it hits the ceiling, that signals throttling
            # (a WAF tarpit), not insufficient budget — raising it would not help.
            DALFOX_DELAY=100
            DALFOX_TIMEOUT=1800         # 30 min safety net
            DALFOX_WORKERS=10
            XSS_CANDIDATE_CAP=100       # distinct injection points
            SQLI_CANDIDATE_CAP=15
            SQLMAP_TIMEOUT=1800         # 30 min
            FFUF_TIMEOUT=300            # 5 min per host
            PHASE8_WALL_TIMEOUT=3600
            PHASE9_WALL_TIMEOUT=3600    # 60 min absolute ceiling
            PHASE10_WALL_TIMEOUT=3600
            PHASE11_WALL_TIMEOUT=3600
            ;;

        # ── DEEP ─────────────────────────────────────────────────────────────
        # Full 12-phase pipeline — everything enabled, no caps reduced.
        # Good for weekly runs or first-time target onboarding.
        # Typical runtime: 1–4+ hours depending on target size.
        deep)
            info "Scan mode: DEEP — full 12-phase pipeline, all phases enabled"

            RUN_DNS_BRUTEFORCE=true
            RUN_PERMUTATIONS=true
            RUN_CLOUD_ENUM=true
            RUN_PORT_SCAN=true
            RUN_PARAM_DISCOVERY=true
            RUN_ASSET_SCORING=true
            RUN_JS_ANALYSIS=true
            RUN_PATTERN_HUNTING=true
            RUN_SCREENSHOTS=true
            RUN_VHOST_DISCOVERY=true
            RUN_FUZZING=true
            RUN_ACTIVE_VULNS=true

            NUCLEI_SEVERITY="critical,high,medium,low"
            KATANA_DEPTH=3
            AMASS_TIMEOUT="${NULLSEC_AMASS_TIMEOUT:-1800}"

            HTTPX_THREADS=30
            NUCLEI_RATE_LIMIT=50
            NUCLEI_CONCURRENCY=25  # deep scans hit larger host sets; keep under MHE (30)
            MAX_JS_FILES=100
            MAX_ARJUN_HOSTS=5
            MAX_SCREENSHOTS=100
            MAX_CORS_HOSTS=200
            MAX_BUCKET_MUTATIONS=500    # deeper bucket name generation in deep mode

            # Phase 9 / 11 timing — deep mode is thorough but polite: slower
            # delay, larger caps, longer safety-net timeouts.  Caps bound DISTINCT
            # INJECTION POINTS (post-dedup).  300 distinct points is already a very
            # large real attack surface — far more meaningful than the old
            # raw-URL cap of 1000, which after dedup almost never bit.  Lower
            # worker count keeps deep scans gentle on the target (politeness >
            # speed for a thorough weekly run).  60 min is a ceiling for genuine
            # hangs; a responsive target finishes 300 points well under it.
            DALFOX_DELAY=200
            DALFOX_TIMEOUT=3600         # 60 min safety net
            DALFOX_WORKERS=6            # gentle concurrency for a polite deep scan
            XSS_CANDIDATE_CAP=300       # distinct injection points
            SQLI_CANDIDATE_CAP=30
            SQLMAP_TIMEOUT=3600         # 60 min
            FFUF_TIMEOUT=600            # 10 min per host
            PHASE8_WALL_TIMEOUT=7200
            PHASE9_WALL_TIMEOUT=7200    # 120 min absolute ceiling
            PHASE10_WALL_TIMEOUT=7200
            PHASE11_WALL_TIMEOUT=7200
            ;;

        *)
            error "Unknown scan mode: '$SCAN_MODE'. Valid options: fast | normal | deep"
            exit 1
            ;;
    esac
}

#==============================================================================#
#                            TOOL CHECKING                                     #
#==============================================================================#

check_tools() {
    print_phase "🔧 CHECKING REQUIRED TOOLS"

    # Mode-aware required tools. A tool is fatal only when an enabled phase truly
    # needs it. Optional validators/crawlers remain optional and are reported
    # without blocking the scan.
    local required_tools=("subfinder" "assetfinder" "jq" "curl")
    if authorization_allowed enumeration; then
        required_tools+=("dnsx" "httpx-toolkit" "katana" "waybackurls" "gau" "unfurl")
    fi
    if authorization_allowed validation; then required_tools+=("nuclei"); fi

    if [ "$RUN_DNS_BRUTEFORCE" = true ] || [ "$RUN_PERMUTATIONS" = true ]; then
        required_tools+=("puredns")
    fi
    if [ "$RUN_PORT_SCAN" = true ]; then
        required_tools+=("naabu")
    fi
    if [ "$RUN_PARAM_DISCOVERY" = true ]; then
        required_tools+=("arjun")
    fi
    if [ "$RUN_VHOST_DISCOVERY" = true ] || [ "$RUN_FUZZING" = true ]; then
        required_tools+=("ffuf")
    fi

    # Optional tools — script skips relevant steps if missing
    local optional_tools=("gotator" "gowitness" "dalfox" "sqlmap" "gf"
        "anew" "qsreplace" "hakrawler" "cariddi" "dig"
        "cloud_enum" "s3scanner" "trufflehog")

    local missing_required=()
    local seen=" "
    local tool unique_required=()
    for tool in "${required_tools[@]}"; do
        if [[ "$seen" != *" $tool "* ]]; then
            unique_required+=("$tool")
            seen+="$tool "
        fi
    done

    echo -e "${CYAN}--- Required Tools for mode: $SCAN_MODE ---${NC}"

    # Amass compatibility: prefer the side-by-side v4 binary for colored
    # FQDN/IP/DNS relationship output, while retaining the maintained binary as
    # a fallback so the framework remains portable.
    local amass_v4_version=""
    if authorization_allowed enumeration; then
    if check_command "$AMASS_V4_BIN"; then
        amass_v4_version=$("$AMASS_V4_BIN" -version 2>&1 | head -n 1 || true)
    fi
    if [ "$AMASS_PREFER_V4" = true ] && [[ "$amass_v4_version" == v4.* ]]; then
        echo -e "  ${GREEN}✓${NC} $AMASS_V4_BIN ($amass_v4_version; preferred colored graph engine)"
    elif check_command "amass"; then
        echo -e "  ${YELLOW}✓${NC} amass (fallback; usable Amass v4 binary not selected)"
    elif [[ "$amass_v4_version" == v4.* ]]; then
        echo -e "  ${GREEN}✓${NC} $AMASS_V4_BIN ($amass_v4_version)"
    else
        echo -e "  ${RED}✗${NC} $AMASS_V4_BIN or amass"
        missing_required+=("$AMASS_V4_BIN|amass")
    fi

    else
        echo "  ○ Amass target enumeration not authorized"
    fi
    for tool in "${unique_required[@]}"; do
        if check_command "$tool"; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${RED}✗${NC} $tool"
            missing_required+=("$tool")
        fi
    done

    echo ""
    echo -e "${CYAN}--- Optional Tools (enhance results) ---${NC}"
    for tool in "${optional_tools[@]}"; do
        if check_command "$tool"; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${YELLOW}○${NC} $tool (not installed — related checks will be skipped/reduced)"
        fi
    done

    echo ""
    echo -e "${CYAN}--- Wordlists / Data Files ---${NC}"
    if [ "$RUN_DNS_BRUTEFORCE" = true ]; then
        check_readable_file "$DNS_WORDLIST" "$DNS_WORDLIST" || true
        check_readable_file "$RESOLVERS" "$RESOLVERS" || true
    else
        echo -e "  ${YELLOW}○${NC} DNS brute-force wordlists not required in $SCAN_MODE mode"
    fi
    if [ "$RUN_PERMUTATIONS" = true ]; then
        check_readable_file "$PERM_WORDLIST" "$PERM_WORDLIST" || true
    else
        echo -e "  ${YELLOW}○${NC} permutation wordlist not required in $SCAN_MODE mode"
    fi
    if [ "$RUN_FUZZING" = true ]; then
        check_readable_file "$WEB_WORDLIST" "$WEB_WORDLIST" || true
        check_readable_file "$SECLISTS/Discovery/Web-Content/raft-large-files.txt" "$SECLISTS/Discovery/Web-Content/raft-large-files.txt" || true
    else
        echo -e "  ${YELLOW}○${NC} web-content fuzzing wordlists not required in $SCAN_MODE mode"
    fi

    echo ""
    echo -e "${CYAN}--- Nuclei Templates ---${NC}"
    if [ -d "$NUCLEI_TEMPLATES" ]; then
        echo -e "  ${GREEN}✓${NC} $NUCLEI_TEMPLATES"
    else
        echo -e "  ${YELLOW}○${NC} not found — run 'nuclei -ut' or set:"
        echo '    export NUCLEI_TEMPLATES="$HOME/.local/nuclei-templates"'
    fi

    if [ ${#missing_required[@]} -ne 0 ]; then
        error "Missing required tools for $SCAN_MODE mode: ${missing_required[*]}"
        error "Install them, change scan mode, or use -s only if you intentionally accept skipped/broken phases. Exiting."
        exit 1
    fi

    echo ""
    success "Required tools for $SCAN_MODE mode are available."
}

#==============================================================================#
#                         DIRECTORY STRUCTURE                                  #
#==============================================================================#

create_structure() {
    print_phase "📁 CREATING DIRECTORY STRUCTURE"

    # Ensure parent directory exists before resolving absolute path
    # (fixes original bug where cd would fail if parent didn't exist)
    local parent_dir
    parent_dir="$(dirname "$OUTPUT_DIR")"
    mkdir -p "$parent_dir"
    OUTPUT_DIR="$(cd "$parent_dir" && pwd)/$(basename "$OUTPUT_DIR")"

    mkdir -p "$OUTPUT_DIR"/{phase1-subdomains,phase2-validation,phase2.5-cloud,phase3-probing,\
phase4-portscan,phase5-urls,phase6-parameters,asset-scoring,phase7-vulns,phase8-javascript,\
phase9-patterns,phase10-screenshots,phase11-fuzzing,phase12-active-vulns,reports}

    mkdir -p "$OUTPUT_DIR/phase10-screenshots"/{403,admin,interesting,all}
    mkdir -p "$OUTPUT_DIR/phase8-javascript/js-files"
    mkdir -p "$OUTPUT_DIR/phase11-fuzzing"/{dirs,vhosts}
    mkdir -p "$OUTPUT_DIR/phase2.5-cloud"/{s3,gcs,azure,exposed}

    success "Directory structure created: $OUTPUT_DIR"
}

#==============================================================================#
#                                USAGE                                         #
#==============================================================================#

print_version() {
    echo "NullSec Framework v${VERSION}"
    echo "Created by ${AUTHOR}"
}

usage() {
    local exit_code="${1:-1}"
    echo "Usage: $0 -d <target-domain> [options]"
    echo ""
    echo "Options:"
    echo "  -d <domain>       Target domain (required)"
    echo "  -o <dir>          Output directory (default: ./recon-<domain>-<timestamp>)"
    echo "  -m <mode>         Scan mode: fast | normal | deep  (default: normal)"
    echo "  -s                Skip tool checking"
    echo "  -u                Update Nuclei templates before scanning"
    echo "  -r                Enable rate limiting / polite delays between phases"
    echo "  -c <dir>          Resume scan from checkpoint in existing output directory"
    echo "  --version         Show NullSec version and author"
    echo "  --help            Show this help message"
    echo "  -I <file>         Approved hosts: exact names or *.domain; default: exact -d"
    echo "  -E <file>         Excluded hosts; exclusions override approvals"
    echo "  -C <file>         Exact cloud approvals: s3:name, gcs:name, azure:name"
    echo "  -A                Authorize target-facing enumeration (off by default)"
    echo "  -V                Authorize active validation (also requires -A)"
    echo "  -K                Authorize secret verification (off by default)"
    echo "  -h                Show this help message"
    echo ""
    echo "Amass compatibility:"
    echo "  NullSec prefers 'amass-v4' for colored FQDN/IP/DNS relationship output"
    echo "  and falls back to 'amass'. Set AMASS_PREFER_V4=false to force fallback."
    echo ""
    echo "Scan Modes:"
    echo "  fast    Passive subdomain sources only, critical Nuclei, no bruteforce/fuzzing"
    echo "          Skips: DNS bruteforce, port scan, JS analysis, fuzzing, active confirm"
    echo "          Runtime: ~5-15 min  |  Good for: hourly scheduled runs"
    echo ""
    echo "  normal  Full discovery + JS analysis + pattern hunting, no heavy active steps"
    echo "          Skips: permutations, Arjun, directory fuzzing, active confirmation"
    echo "          Runtime: ~30-60 min  |  Good for: daily scheduled runs"
    echo ""
    echo "  deep    Full 12-phase pipeline — everything enabled, all caps raised"
    echo "          Runtime: 1-4+ hours  |  Good for: weekly runs, new target onboarding"
    echo ""
    echo "Examples:"
    echo "  $0 -d example.com"
    echo "  $0 -d example.com -m fast"
    echo "  $0 -d example.com -m deep -u -r"
    echo "  $0 -d example.com -m normal -o /path/to/output"
    exit "$exit_code"
}

#==============================================================================#
#                              PHASE FUNCTIONS                                 #
#==============================================================================#

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1: Subdomain Discovery
# ─────────────────────────────────────────────────────────────────────────────
phase1_subdomain_discovery() {
    phase_done 1 && { polite_sleep; return 0; }
    print_phase "🔍 PHASE 1: SUBDOMAIN DISCOVERY"

    local p1dir="$OUTPUT_DIR/phase1-subdomains"
    local phase_errors=0 rc tmp
    backup_phase_outputs "$p1dir"

    info "Running Subfinder (passive)..."
    : > "$p1dir/subfinder.txt"
    if ! authorized_run passive host "$TARGET" subfinder -d @AUTHORIZED_INPUT@ -all -silent -o "$p1dir/subfinder.txt" 2>/dev/null; then
        warn "Subfinder failed; preserving any partial output."
        phase_errors=$(( phase_errors + 1 ))
    fi
    success "Subfinder: $(count_lines "$p1dir/subfinder.txt") subdomains"

    info "Running Amass enumeration with timeout: ${AMASS_TIMEOUT}s"
    local amass_help amass_state amass_export amass_log amass_bin amass_version
    local amass_minutes amass_detailed amass_clean amass_legacy amass_clean_log amass_raw
    local -a amass_config_args=()
    amass_clean="$p1dir/amass-clean.txt"
    amass_legacy="$p1dir/amass.txt"
    amass_clean_log="$p1dir/amass-clean-export.log"
    : > "$amass_clean"
    : > "$amass_legacy"
    : > "$amass_clean_log"
    : > "$p1dir/amass-detailed.txt"

    # Amass v4 detailed output is a relationship graph. It is useful for
    # diagnostics, but it must never be merged directly into all-subdomains.txt.
    # This cleaner extracts only clean, in-scope FQDN tokens and removes graph
    # relationship/object lines such as Netblock, IPAddress, ASN, ns_record, etc.
    _nullsec_export_clean_amass() {
        local input="$1" output="$2"
        if [ -s "$input" ]; then
            grep -Eiv 'Netblock|IPAddress|RIROrganization|ASN|contains|managed_by|announces|ns_record|mx_record' "$input" 2>/dev/null \
                | grep -Eo '(\*\.)?([a-zA-Z0-9_-]+\.)+[a-zA-Z0-9_-]+' \
                | sed -E 's/^\*\.//; s/\.$//' \
                | tr '[:upper:]' '[:lower:]' \
                | in_scope \
                | sort -u > "$output" || : > "$output"
        else
            : > "$output"
        fi
    }
    # Run Amass v4 without redirecting stdout. Keeping stdout attached to the
    # terminal is intentional: it preserves v4's live ANSI colors and its rich
    # Open Asset Model relationships while -o independently saves plain text.
    _nullsec_run_amass_v4() {
        local bin="$1"
        amass_bin="$bin"
        amass_state="$p1dir/.amass-v4-state"
        amass_log="$p1dir/amass-v4.log"
        amass_detailed="$p1dir/amass-detailed.txt"
        amass_minutes=$(( (AMASS_TIMEOUT + 59) / 60 ))
        [ "$amass_minutes" -lt 1 ] && amass_minutes=1
        amass_config_args=()

        rm -rf "$amass_state"
        mkdir -p "$amass_state"
        : > "$amass_log"
        : > "$amass_detailed"
        "$amass_bin" -version > "$p1dir/amass-version.txt" 2>&1 || true

        if [ -s "$AMASS_V4_CONFIG" ]; then
            amass_config_args=(-config "$AMASS_V4_CONFIG")
        fi

        _run_tracked_command authorized_run enumeration host "$TARGET" timeout --signal=INT --kill-after=30s "$(( AMASS_TIMEOUT + 45 ))"             "$amass_bin" enum                 "${amass_config_args[@]}"                 -timeout "$amass_minutes"                 -d @AUTHORIZED_INPUT@                 -dir "$amass_state"                 -log "$amass_log"                 -o "$amass_detailed"
        rc=$?

        # Export only clean, in-scope FQDNs. Keep the full graph separately for
        # diagnostics; never merge raw graph relationship lines downstream.
        _nullsec_export_clean_amass "$amass_detailed" "$amass_clean"
    }

    if authorization_allowed enumeration; then
    amass_version=""
    if [ "$AMASS_PREFER_V4" = true ] && check_command "$AMASS_V4_BIN"; then
        amass_version=$("$AMASS_V4_BIN" -version 2>&1 | head -n 1 || true)
    fi

    if [ "$AMASS_PREFER_V4" = true ] && [[ "$amass_version" == v4.* ]]; then
        _nullsec_run_amass_v4 "$(command -v "$AMASS_V4_BIN")"

    elif check_command "amass"; then
        # The normal binary can itself be v4, in which case preserve the same
        # graph experience. Otherwise use the maintained v5 database/export flow.
        amass_bin=$(command -v amass)
        amass_version=$("$amass_bin" -version 2>&1 | head -n 1 || true)
        amass_help=$("$amass_bin" enum -h 2>&1 || true)

        if [[ "$amass_version" == v4.* ]]; then
            _nullsec_run_amass_v4 "$amass_bin"
        elif grep -q -- '-src' <<< "$amass_help"; then
            # Older Amass fallback. This path is retained only for portability;
            # it does not provide the v4 Open Asset Model relationship display.
            info "Using installed pre-v4 Amass fallback."
            amass_raw="$p1dir/.amass-raw.tmp.$$"
            : > "$amass_raw"
            _run_tracked_command authorized_run enumeration host "$TARGET" timeout --signal=INT --kill-after=30s "$AMASS_TIMEOUT"                 "$amass_bin" enum                     -passive -src -d @AUTHORIZED_INPUT@                     -o "$amass_raw"                     2> "$p1dir/amass-error.log"
            rc=$?
            _nullsec_export_clean_amass "$amass_raw" "$amass_clean"
            rm -f "$amass_raw"
        else
            info "Using installed Amass v5 database/export fallback."
            amass_state="$p1dir/.amass-state"
            amass_export="$p1dir/.amass-export.tmp.$$"
            amass_log="$amass_state/amass.log"

            rm -rf "$amass_state"
            mkdir -p "$amass_state"
            rm -f "$amass_export"

            local -a amass_v5_config_args=()
            if [ -s "$HOME/.config/amass/config.yaml" ]; then
                amass_v5_config_args=(-config "$HOME/.config/amass/config.yaml")
            fi

            _run_tracked_command authorized_run enumeration host "$TARGET" timeout --signal=INT --kill-after=30s "$AMASS_TIMEOUT"                 "$amass_bin" enum                     "${amass_v5_config_args[@]}"                     -d @AUTHORIZED_INPUT@                     -nocolor                     -dir "$amass_state"                     -log amass.log                     >/dev/null 2>&1
            rc=$?

            if "$amass_bin" subs                 -names -nocolor                 -d "$TARGET"                 -dir "$amass_state"                 -o "$amass_export"                 >/dev/null 2>> "$amass_log"; then
                if [ -s "$amass_export" ]; then
                    _nullsec_export_clean_amass "$amass_export" "$amass_clean"
                fi
            else
                warn "Amass v5 result export failed; see $amass_log"
                phase_errors=$(( phase_errors + 1 ))
            fi
            rm -f "$amass_export"
        fi
    else
        error "Neither a valid $AMASS_V4_BIN nor amass is available."
        rc=127
        phase_errors=$(( phase_errors + 1 ))
    fi

    else
        info "Amass target enumeration skipped: -A was not supplied."
        rc=0
    fi
    unset -f _nullsec_run_amass_v4 _nullsec_export_clean_amass

    # Legacy compatibility: keep amass.txt as a clean hostname-only copy, while
    # the explicit amass-clean.txt file is the source used by merges.
    cp -f "$amass_clean" "$amass_legacy" 2>/dev/null || : > "$amass_legacy"

    local amass_clean_count
    amass_clean_count=$(count_lines "$amass_clean")
    printf 'Amass clean subdomains exported: %s\n' "$amass_clean_count" > "$amass_clean_log"
    if [ "$rc" -eq 124 ]; then
        warn "Amass reached the timeout. This does not mean the scan failed. Increase NULLSEC_AMASS_TIMEOUT if needed."
        [ -s "$p1dir/amass-detailed.txt" ] && warn "Partial Amass graph output was preserved: $p1dir/amass-detailed.txt"
    elif [ "$rc" -ne 0 ]; then
        warn "Amass failed with exit code $rc; review the Amass log."
        phase_errors=$(( phase_errors + 1 ))
    fi

    if [ -s "$p1dir/amass-detailed.txt" ]; then
        info "Amass detailed graph saved for diagnostics: $p1dir/amass-detailed.txt"
    fi

    if [ "$amass_clean_count" -gt 0 ]; then
        success "Amass clean subdomains exported: $amass_clean_count"
    else
        info "Amass graph saved for diagnostics. Continuing with other sources."
    fi

    info "Running Assetfinder..."
    tmp="$p1dir/.assetfinder.tmp.$$"
    if authorized_run passive host "$TARGET" assetfinder --subs-only @AUTHORIZED_INPUT@ > "$tmp" 2>/dev/null; then
        mv -f "$tmp" "$p1dir/assetfinder.txt"
    else
        warn "Assetfinder failed."
        rm -f "$tmp"
        : > "$p1dir/assetfinder.txt"
        phase_errors=$(( phase_errors + 1 ))
    fi
    success "Assetfinder: $(count_lines "$p1dir/assetfinder.txt") subdomains"

    info "Querying crt.sh (Certificate Transparency)..."
    local crt_body crt_tmp crt_code
    crt_body="$p1dir/.crtsh-response.tmp.$$"
    crt_tmp="$p1dir/.crtsh-results.tmp.$$"

    crt_code=$(authorized_run passive service "https://crt.sh/?q=%25.$TARGET&output=json" curl -q --proto '=https' --max-redirs 0 -sS         --connect-timeout 10         --max-time 45         --retry 4         --retry-delay 5         --retry-max-time 180         --retry-all-errors         -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"         -o "$crt_body"         -w '%{http_code}'         "https://crt.sh/?q=%25.$TARGET&output=json"         2>/dev/null || true)

    if [ "$crt_code" = "200" ]        && jq -e 'type == "array"' "$crt_body" >/dev/null 2>&1; then

        if jq -r '.[]?.name_value // empty' "$crt_body"             | sed 's/\*\.//g'             | tr '[:upper:]' '[:lower:]'             | in_scope             | sort -u > "$crt_tmp"; then

            mv -f "$crt_tmp" "$p1dir/crtsh.txt"
        else
            warn "crt.sh response parsing failed; keeping previous results."
            rm -f "$crt_tmp"
            [ -f "$p1dir/crtsh.txt" ] || : > "$p1dir/crtsh.txt"
        fi
    else
        warn "crt.sh unavailable or returned invalid JSON (HTTP ${crt_code:-curl-error}); keeping previous results."
        rm -f "$crt_tmp"
        [ -f "$p1dir/crtsh.txt" ] || : > "$p1dir/crtsh.txt"
    fi

    rm -f "$crt_body" "$crt_tmp"

    # crt.sh is an optional external passive source. Its temporary outage must
    # not freeze the Phase 1 checkpoint or invalidate successful source results.
    success "crt.sh: $(count_lines "$p1dir/crtsh.txt") subdomains"

    info "Merging passive enumeration results..."
    if ! cat "$p1dir/subfinder.txt" "$p1dir/amass-clean.txt" \
        "$p1dir/assetfinder.txt" "$p1dir/crtsh.txt" 2>/dev/null \
        | in_scope | sort -u > "$p1dir/all-subdomains-passive.txt"; then
        error "Failed to merge passive subdomain sources."
        merge_phase_backup "$p1dir"
        return 1
    fi
    success "Unique passive subdomains: $(count_lines "$p1dir/all-subdomains-passive.txt")"

    if authorization_allowed enumeration && check_command "hakrawler" && [ -s "$p1dir/all-subdomains-passive.txt" ]; then
        info "Running Hakrawler for response-based subdomain discovery..."
        local target_escaped hakrawler_raw
        target_escaped=$(printf '%s' "$TARGET" | sed 's/\./\\./g')
        hakrawler_raw="$p1dir/.hakrawler-raw.tmp.$$"
        if sed 's|^|https://|' "$p1dir/all-subdomains-passive.txt" \
            | authorized_run enumeration stream "" httpx-toolkit -silent 2>/dev/null \
            | authorized_run enumeration stream "" hakrawler -subs -d 2 -timeout 10 -u 2>/dev/null > "$hakrawler_raw"; then
            grep -oE "[a-zA-Z0-9._-]+\.$target_escaped" "$hakrawler_raw" 2>/dev/null \
                | sort -u > "$p1dir/hakrawler.txt" || : > "$p1dir/hakrawler.txt"
        else
            warn "Hakrawler pipeline failed."
            : > "$p1dir/hakrawler.txt"
            phase_errors=$(( phase_errors + 1 ))
        fi
        rm -f "$hakrawler_raw"
        success "Hakrawler: $(count_lines "$p1dir/hakrawler.txt") subdomains"
    else
        : > "$p1dir/hakrawler.txt"
    fi

    if [ "$RUN_DNS_BRUTEFORCE" = true ]; then
        if [ -s "$DNS_WORDLIST" ] && [ -r "$DNS_WORDLIST" ] && [ -s "$RESOLVERS" ] && [ -r "$RESOLVERS" ]; then
            info "Running Puredns bruteforce..."
            : > "$p1dir/puredns.txt"
            if ! authorized_run enumeration dns-wordlist "$DNS_WORDLIST" puredns bruteforce @AUTHORIZED_INPUT@ "$TARGET" \
                -r "$RESOLVERS" --rate-limit 200 \
                -w "$p1dir/puredns.txt" 2>/dev/null; then
                warn "Puredns bruteforce failed; partial output was preserved."
                phase_errors=$(( phase_errors + 1 ))
            fi
            success "Puredns bruteforce: $(count_lines "$p1dir/puredns.txt") subdomains"
        else
            warn "Wordlist or resolvers file not available — skipping DNS bruteforce."
            : > "$p1dir/puredns.txt"
        fi
    else
        info "DNS bruteforce skipped (mode: $SCAN_MODE)."
        : > "$p1dir/puredns.txt"
    fi

    # Include Hakrawler discoveries in the canonical Phase 1 output.
    cat "$p1dir/all-subdomains-passive.txt" "$p1dir/hakrawler.txt" \
        "$p1dir/puredns.txt" 2>/dev/null | sort -u > "$p1dir/all-subdomains.txt"

    if [ "$RUN_PERMUTATIONS" = true ] && check_command "gotator" \
       && [ -s "$PERM_WORDLIST" ] && [ -r "$PERM_WORDLIST" ] \
       && [ -s "$RESOLVERS" ] && [ -r "$RESOLVERS" ]; then
        info "Generating subdomain permutations with Gotator..."
        if ! gotator -sub "$p1dir/all-subdomains.txt" -perm "$PERM_WORDLIST" \
            -depth 1 -silent > "$p1dir/permutations-raw.txt" 2>/dev/null; then
            warn "Gotator failed."
            phase_errors=$(( phase_errors + 1 ))
            : > "$p1dir/permutations-raw.txt"
        fi

        info "Resolving permutations with Puredns..."
        : > "$p1dir/permutations-resolved.txt"
        if [ -s "$p1dir/permutations-raw.txt" ] && ! authorized_run enumeration list "$p1dir/permutations-raw.txt" puredns resolve @AUTHORIZED_INPUT@ \
            -r "$RESOLVERS" -w "$p1dir/permutations-resolved.txt" 2>/dev/null; then
            warn "Puredns permutation resolution failed; partial output was preserved."
            phase_errors=$(( phase_errors + 1 ))
        fi

        if [ -s "$p1dir/permutations-resolved.txt" ]; then
            if check_command "anew"; then
                anew "$p1dir/all-subdomains.txt" < "$p1dir/permutations-resolved.txt" >/dev/null
            else
                cat "$p1dir/all-subdomains.txt" "$p1dir/permutations-resolved.txt" \
                    | sort -u > "$p1dir/all-subdomains-tmp.txt"
                mv -f "$p1dir/all-subdomains-tmp.txt" "$p1dir/all-subdomains.txt"
            fi
        fi
        success "Permutations added: $(count_lines "$p1dir/permutations-resolved.txt") subdomains"
    elif [ "$RUN_PERMUTATIONS" = false ]; then
        info "Permutation generation skipped (mode: $SCAN_MODE)."
    else
        warn "Gotator/wordlist/resolvers not available — skipping permutations."
    fi

    local p1_total
    p1_total=$(count_lines "$p1dir/all-subdomains.txt")
    merge_phase_backup "$p1dir"

    if [ "$p1_total" -eq 0 ]; then
        error "Phase 1 produced no subdomains."
        return 1
    fi

    success "Phase 1 complete! Total subdomains: $p1_total"
    notify "🌐 Phase 1 Complete" \
        "Subdomain discovery finished.\nFound *${p1_total}* subdomains for \`${TARGET}\`."

    if [ "$phase_errors" -gt 0 ]; then
        warn "Phase 1 completed with $phase_errors source failure(s); checkpoint was not advanced so resume can retry."
        return 1
    fi

    save_checkpoint 1
    polite_sleep
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2: Validation & Resolution
# ─────────────────────────────────────────────────────────────────────────────
phase2_validation() {
    authorization_allowed enumeration || { info "phase2_validation: skipped by authorization policy"; return 0; }
    phase_done 2 && { polite_sleep; return 0; }
    print_phase "✅ PHASE 2: VALIDATION & RESOLUTION"

    local p1dir="$OUTPUT_DIR/phase1-subdomains"
    local p2dir="$OUTPUT_DIR/phase2-validation"
    local phase_errors=0

    if [ ! -s "$p1dir/all-subdomains.txt" ]; then
        error "No subdomains found in Phase 1. Skipping Phase 2."
        return 1
    fi
    backup_phase_outputs "$p2dir"

    # 2.1 Resolve with dnsx — collect A records and detect wildcards
    info "Resolving subdomains with dnsx..."
    : > "$p2dir/resolved.txt"
    : > "$p2dir/valid-subdomains.txt"
    : > "$p2dir/wildcards.txt"

    local resolvers_file="$p2dir/resolvers.txt"
    printf '8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n9.9.9.9\n208.67.222.222\n' > "$resolvers_file"

    if ! authorized_run enumeration list "$p1dir/all-subdomains.txt" dnsx -l @AUTHORIZED_INPUT@ \
        -r "$resolvers_file" \
        -o "$p2dir/resolved.txt" \
        -wd "$p2dir/wildcards.txt" \
        -a -resp -silent -rl 100 2>"$p2dir/dnsx-error.log"; then
        warn "dnsx failed; see $p2dir/dnsx-error.log. Partial output was preserved."
        phase_errors=$(( phase_errors + 1 ))
    fi

    # 2.2 Extract clean subdomain list. dnsx output begins with the hostname.
    if [ -s "$p2dir/resolved.txt" ]; then
        awk '{print $1}' "$p2dir/resolved.txt" | sed 's/\.$//' | in_scope | sort -u > "$p2dir/valid-subdomains.txt"
    fi

    local total_enum valid wildcards
    total_enum=$(count_lines "$p1dir/all-subdomains.txt")
    valid=$(count_lines "$p2dir/valid-subdomains.txt")
    wildcards=$(count_lines "$p2dir/wildcards.txt")

    info "Total enumerated  : $total_enum"
    info "Actually resolved : $valid"
    info "Wildcards filtered: $wildcards"

    if [ "$valid" -eq 0 ]; then
        warn "Phase 2 produced 0 valid subdomains. Later web phases will be skipped or empty."
    fi

    # 2.3 Subdomain takeover scanning
    : > "$p2dir/takeover-findings.txt"
    if [ -s "$p2dir/valid-subdomains.txt" ]; then
        if authorization_allowed validation && [ -d "$NUCLEI_TEMPLATES/http/takeovers" ]; then
            info "Scanning for subdomain takeover vulnerabilities..."
            if ! authorized_run validation list "$p2dir/valid-subdomains.txt" nuclei -l @AUTHORIZED_INPUT@ \
                -t "$NUCLEI_TEMPLATES/http/takeovers/" \
                -o "$p2dir/takeover-findings.txt" \
                -silent 2>"$p2dir/takeover-nuclei.log"; then
                warn "Nuclei takeover scan failed; see $p2dir/takeover-nuclei.log."
                phase_errors=$(( phase_errors + 1 ))
            fi

            if [ -s "$p2dir/takeover-findings.txt" ]; then
                success "🚨 Potential takeover vulnerabilities found! → $p2dir/takeover-findings.txt"
            else
                info "No takeover vulnerabilities detected."
            fi
        else
            if ! authorization_allowed validation; then
                info "Takeover scan skipped: active validation was not authorized."
            else
                warn "Takeover template directory missing: $NUCLEI_TEMPLATES/http/takeovers/ — skipping takeover scan."
            fi
        fi
    fi

    merge_phase_backup "$p2dir"
    success "Phase 2 complete! Valid subdomains: $valid"

    if [ "$phase_errors" -gt 0 ]; then
        warn "Phase 2 completed with $phase_errors error(s); checkpoint was not advanced."
        return 1
    fi

    save_checkpoint 2
    polite_sleep
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2.5: Cloud Storage Enumeration
# Tests AWS S3, Google Cloud Storage, and Azure Blob Storage for:
#   - Publicly readable buckets (information disclosure)
#   - Publicly writable buckets (critical — arbitrary file upload)
#   - Bucket existence (even non-public buckets confirm infrastructure)
#
# Name generation strategy:
#   Takes the base target (e.g. "acme.com" → "acme") and all discovered
#   subdomains, then generates permutations with common cloud naming patterns
#   (acme-backup, acme-dev, acme-assets, acme-prod, etc.)
#
# Output feeds into:
#   - Phase 5: exposed bucket URLs added to all-urls.txt
#   - Phase 7: exposed buckets added to Nuclei target list
#   - Report:  dedicated cloud findings section
# ─────────────────────────────────────────────────────────────────────────────
phase2_5_cloud_enum() {
    authorization_allowed enumeration || { info "phase2_5_cloud_enum: skipped by authorization policy"; return 0; }
    # Phase 3 can only have completed after Phase 2.5 was reached. On resume from
    # checkpoint 3 or later, do not rerun cloud enumeration and append stale data.
    local resume_int="${RESUME_FROM%.*}"
    if [ "${resume_int:-0}" -ge 3 ]; then
        info "Phase 2.5 already completed before checkpoint $RESUME_FROM — skipping."
        return 0
    fi

    print_phase "☁️  PHASE 2.5: CLOUD STORAGE ENUMERATION"

    if [ "$RUN_CLOUD_ENUM" = false ]; then
        info "Cloud storage enumeration skipped (mode: $SCAN_MODE)."
        return 0
    fi

    local p2dir="$OUTPUT_DIR/phase2-validation"
    local cdir="$OUTPUT_DIR/phase2.5-cloud"
    backup_phase_outputs "$cdir"

    local base_name
    base_name=$(printf '%s' "$TARGET" \
        | sed -E 's/^(.*\.)?([a-z0-9-]+)\.(com|net|org|edu|gov|mil|int)\.[a-z]{2}$/\2/; t done
                  s/^(.*\.)?([a-z0-9-]+)\.[a-z0-9-]{2,}\.[a-z]{2}$/\2/; t done
                  s/^(.*\.)?([a-z0-9-]+)\.[a-z]{2,}$/\2/
                  :done')

    info "Generating cloud-name candidates..."
    local token_file="$cdir/.tokens.txt"
    local candidates_file="$cdir/.candidates.txt"
    {
        printf '%s\n' "$base_name"
        if [ -s "$p2dir/valid-subdomains.txt" ]; then
            awk -v target="$TARGET" '
                {
                    host=tolower($1)
                    suffix="." tolower(target)
                    if (length(host) > length(suffix) && substr(host,length(host)-length(suffix)+1)==suffix) {
                        host=substr(host,1,length(host)-length(suffix))
                    }
                    n=split(host,parts,".")
                    for(i=1;i<=n;i++) if(parts[i] !~ /^(www|mail|ns[0-9]*|ftp|smtp|pop|imap|vpn|cdn)$/) print parts[i]
                }
            ' "$p2dir/valid-subdomains.txt"
        fi
    } | grep -E '^[a-z0-9][a-z0-9-]{2,62}$' | sort -u > "$token_file"

    local suffixes=("" "-backup" "-backups" "-bak" "-prod" "-production"
        "-dev" "-development" "-staging" "-stage" "-test" "-testing"
        "-qa" "-uat" "-assets" "-static" "-media" "-uploads" "-files"
        "-data" "-logs" "-archive" "-public" "-private" "-internal"
        "-config" "-configs" "-deploy" "-releases" "-builds" "-ci"
        "-images" "-img" "-videos" "-docs" "-documents" "-reports"
        "-api" "-app" "-web" "-mobile" "-frontend" "-backend" "-infra")
    {
        local token suffix
        while IFS= read -r token; do
            for suffix in "${suffixes[@]}"; do
                printf '%s\n' "${token}${suffix}" "${token//-/.}${suffix}"
            done
        done < "$token_file"
    } | tr '[:upper:]' '[:lower:]' \
      | grep -E '^[a-z0-9][a-z0-9.-]{2,61}[a-z0-9]$' \
      | sort -u | head -n "$MAX_BUCKET_MUTATIONS" > "$candidates_file"

    # Global cloud namespaces cannot be attributed from a plausible name alone.
    # CNAMEs and page URLs provide reference leads only. Exact provider/resource
    # approval is required separately and rechecked before each request.
    info "Collecting cloud reference leads (references do not authorize probes)..."
    local ownership_evidence="$cdir/ownership-evidence.txt"
    local ownership_names="$cdir/ownership-corroborated-names.txt"
    local s3_candidates="$cdir/.verified-s3.txt"
    local gcs_candidates="$cdir/.verified-gcs.txt"
    local azure_candidates="$cdir/.verified-azure.txt"
    local unverified_candidates="$cdir/exposed/unverified-candidates.txt"
    : > "$ownership_evidence"
    : > "$ownership_names"
    : > "$s3_candidates"
    : > "$gcs_candidates"
    : > "$azure_candidates"
    : > "$unverified_candidates"

    if check_command "dig" && [ -s "$p2dir/valid-subdomains.txt" ]; then
        while IFS= read -r host; do
            while IFS= read -r cname; do
                [ -n "$cname" ] && printf 'DNS %s CNAME %s\n' "$host" "$cname" >> "$ownership_evidence"
            done < <(authorized_run enumeration host "$host" dig +short CNAME @AUTHORIZED_INPUT@ 2>/dev/null | sed 's/\.$//')
        done < <(head -50 "$p2dir/valid-subdomains.txt")
    fi

    {
        printf '%s\n' "$TARGET"
        [ -s "$p2dir/valid-subdomains.txt" ] && head -20 "$p2dir/valid-subdomains.txt"
    } | sort -u | while IFS= read -r host; do
        local body="" scheme
        for scheme in https http; do
            body=$(authorized_run enumeration host "$scheme://$host/" curl -q --proto '=http,https' --max-redirs 0 -fsS --max-time 8 --max-filesize 1048576 \
                -A "Mozilla/5.0 (compatible; NullSec/ownership-check)" \
                @AUTHORIZED_INPUT@ 2>/dev/null) && break
        done
        [ -n "$body" ] && printf 'HTTP %s\n%s\n' "$host" "$body" >> "$ownership_evidence"
    done

    # References remain provider-specific and never grant authorization.
    # Keep legacy evidence filenames for compatibility with current reports.
    {
        grep -Eoi '[a-z0-9][a-z0-9.-]{2,61}[a-z0-9]\.s3([.-][a-z0-9-]+)?\.amazonaws\.com' "$ownership_evidence" 2>/dev/null \
            | sed -E 's/\.s3([.-][a-z0-9-]+)?\.amazonaws\.com$//I'
        grep -Eoi 's3([.-][a-z0-9-]+)?\.amazonaws\.com/[a-z0-9][a-z0-9.-]{2,61}[a-z0-9]' "$ownership_evidence" 2>/dev/null \
            | sed -E 's#^s3([.-][a-z0-9-]+)?\.amazonaws\.com/##I'
    } | tr '[:upper:]' '[:lower:]' \
      | grep -E '^[a-z0-9][a-z0-9.-]{2,61}[a-z0-9]$' \
      | sort -u | head -n "$MAX_BUCKET_MUTATIONS" > "$s3_candidates"

    {
        grep -Eoi '[a-z0-9][a-z0-9._-]{2,61}[a-z0-9]\.storage\.googleapis\.com' "$ownership_evidence" 2>/dev/null \
            | sed -E 's/\.storage\.googleapis\.com$//I'
        grep -Eoi 'storage\.googleapis\.com/[a-z0-9][a-z0-9._-]{2,61}[a-z0-9]' "$ownership_evidence" 2>/dev/null \
            | sed -E 's#^storage\.googleapis\.com/##I'
    } | tr '[:upper:]' '[:lower:]' \
      | grep -E '^[a-z0-9][a-z0-9._-]{2,61}[a-z0-9]$' \
      | sort -u | head -n "$MAX_BUCKET_MUTATIONS" > "$gcs_candidates"

    grep -Eoi '[a-z0-9][a-z0-9-]{2,62}\.blob\.core\.windows\.net' "$ownership_evidence" 2>/dev/null \
        | sed -E 's/\.blob\.core\.windows\.net$//I' \
        | tr '[:upper:]' '[:lower:]' \
        | grep -E '^[a-z0-9][a-z0-9-]{2,62}$' \
        | sort -u | head -n "$MAX_BUCKET_MUTATIONS" > "$azure_candidates"

    cat "$s3_candidates" "$gcs_candidates" "$azure_candidates" 2>/dev/null \
        | sort -u > "$ownership_names"

    local approval_tmp provider candidate_file
    for provider in s3 gcs azure; do
        case "$provider" in
            s3) candidate_file="$s3_candidates" ;;
            gcs) candidate_file="$gcs_candidates" ;;
            azure) candidate_file="$azure_candidates" ;;
        esac
        approval_tmp=$(mktemp "${TMPDIR:-/tmp}/nullsec-cloud-approved.XXXXXX") || return 1
        if ! cloud_approved_names "$provider" < "$candidate_file" > "$approval_tmp" \
           || ! mv -f "$approval_tmp" "$candidate_file"; then
            rm -f "$approval_tmp"
            return 1
        fi
    done

    if [ -s "$candidates_file" ]; then
        if [ -s "$ownership_names" ]; then
            grep -Fvx -f "$ownership_names" "$candidates_file" 2>/dev/null \
                | sed 's/$/  # NOT PROBED: no provider-specific target ownership evidence/' \
                > "$unverified_candidates" || true
        else
            sed 's/$/  # NOT PROBED: no provider-specific target ownership evidence/' \
                "$candidates_file" > "$unverified_candidates"
        fi
    fi

    local verified_count s3_verified_count gcs_verified_count azure_verified_count
    s3_verified_count=$(count_lines "$s3_candidates")
    gcs_verified_count=$(count_lines "$gcs_candidates")
    azure_verified_count=$(count_lines "$azure_candidates")
    verified_count=$(( s3_verified_count + gcs_verified_count + azure_verified_count ))
    info "Explicitly approved, referenced cloud resources: S3=$s3_verified_count GCS=$gcs_verified_count Azure=$azure_verified_count"

    local s3_exists="$cdir/s3/exists.txt"
    local s3_readable="$cdir/s3/readable.txt"
    local s3_writable="$cdir/s3/writable.txt"
    local gcs_exists="$cdir/gcs/exists.txt"
    local gcs_readable="$cdir/gcs/readable.txt"
    local gcs_writable="$cdir/gcs/writable.txt"
    local gcs_unverified="$cdir/gcs/unverified.txt"
    local az_exists="$cdir/azure/exists.txt"
    local az_readable="$cdir/azure/readable.txt"
    local az_cdn_refs="$cdir/azure/cdn-references.txt"
    local cloud_enum_open="$cdir/exposed/cloud_enum-open.txt"
    : > "$s3_exists"; : > "$s3_readable"; : > "$s3_writable"
    : > "$gcs_exists"; : > "$gcs_readable"; : > "$gcs_writable"; : > "$gcs_unverified"
    : > "$az_exists"; : > "$az_readable"; : > "$az_cdn_refs"; : > "$cloud_enum_open"

    if [ "$s3_verified_count" -gt 0 ]; then
        info "Testing explicitly approved, referenced AWS S3 buckets..."
        _check_s3_bucket() {
            local name="$1" exists_file="$2" readable_file="$3" writable_file="$4"
            cloud_resource_allowed "s3:$name" || return 0
            local url="https://${name}.s3.amazonaws.com" rc acl_resp policy_resp
            rc=$(authorized_cloud_curl "s3:$name" -sS --max-time 8 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || printf '000')
            case "$rc" in
                200) printf '%s\n' "$url" >> "$exists_file"; printf '%s\n' "$url" >> "$readable_file" ;;
                301|307|401|403) printf '%s\n' "$url" >> "$exists_file" ;;
                *) return 0 ;;
            esac

            # ACL and policy checks are independent of anonymous object listing.
            acl_resp=$(authorized_cloud_curl "s3:$name" -sS --max-time 5 "${url}?acl" 2>/dev/null || true)
            if printf '%s' "$acl_resp" | awk '
                BEGIN { RS="</Grant>"; found=0 }
                /acs\.amazonaws\.com\/groups\/global\/AllUsers/ \
                    && /<Permission>(WRITE|WRITE_ACP|FULL_CONTROL)<\/Permission>/ { found=1 }
                END { exit(found ? 0 : 1) }
            '; then
                printf '%s\n' "$url" >> "$writable_file"
                return 0
            fi

            policy_resp=$(authorized_cloud_curl "s3:$name" -sS --max-time 5 "${url}?policy" 2>/dev/null || true)
            if command -v jq >/dev/null 2>&1 && printf '%s' "$policy_resp" | jq -e '
                def public_principal:
                    . == "*"
                    or (type == "object" and (
                        (.AWS? == "*")
                        or ((.AWS? | type) == "array" and ((.AWS | index("*")) != null))
                    ));
                .Statement[]?
                | select(.Effect == "Allow")
                | select(.Principal | public_principal)
                | select((.Condition? // {}) | length == 0)
                | (.Action | if type == "array" then .[] else . end)
                | select(. == "s3:*" or . == "s3:PutObject" or . == "s3:PutObjectAcl")
            ' >/dev/null 2>&1; then
                printf '%s\n' "$url" >> "$writable_file"
            fi
        }
        export -f _check_s3_bucket
        xargs -r -P "$CLOUD_ENUM_THREADS" -I {} \
            bash -c 'set -uo pipefail; _check_s3_bucket "$@"' _ {} \
            "$s3_exists" "$s3_readable" "$s3_writable" \
            < "$s3_candidates" 2>/dev/null
        unset -f _check_s3_bucket
    fi

    if [ "$gcs_verified_count" -gt 0 ]; then
        info "Testing explicitly approved, referenced Google Cloud Storage buckets..."
        _check_gcs_bucket() {
            local name="$1" exists_file="$2" readable_file="$3" writable_file="$4"
            cloud_resource_allowed "gcs:$name" || return 0
            local url="https://storage.googleapis.com/${name}" meta_rc list_resp iam_resp
            meta_rc=$(authorized_cloud_curl "gcs:$name" -sS --max-time 8 -o /dev/null -w '%{http_code}' \
                "https://storage.googleapis.com/storage/v1/b/${name}" 2>/dev/null || printf '000')
            case "$meta_rc" in
                200|401|403) printf '%s\n' "$url" >> "$exists_file" ;;
                *) return 0 ;;
            esac

            list_resp=$(authorized_cloud_curl "gcs:$name" -sS --max-time 8 \
                "https://storage.googleapis.com/storage/v1/b/${name}/o?maxResults=10" 2>/dev/null || true)
            if command -v jq >/dev/null 2>&1 \
               && printf '%s' "$list_resp" | jq -e 'select(.kind == "storage#objects" and (.error? | not))' >/dev/null 2>&1; then
                printf '%s\n' "$url" >> "$readable_file"
            fi

            # Evaluate public write IAM even when object listing is denied.
            iam_resp=$(authorized_cloud_curl "gcs:$name" -sS --max-time 5 \
                "https://storage.googleapis.com/storage/v1/b/${name}/iam" 2>/dev/null || true)
            if command -v jq >/dev/null 2>&1 && printf '%s' "$iam_resp" | jq -e '
                .bindings[]?
                | select((.condition? // null) == null)
                | select(.role == "roles/storage.objectCreator"
                      or .role == "roles/storage.objectAdmin"
                      or .role == "roles/storage.legacyBucketWriter"
                      or .role == "roles/storage.admin")
                | .members[]?
                | select(. == "allUsers")
            ' >/dev/null 2>&1; then
                printf '%s\n' "$url" >> "$writable_file"
            fi
        }
        export -f _check_gcs_bucket
        xargs -r -P "$CLOUD_ENUM_THREADS" -I {} \
            bash -c 'set -uo pipefail; _check_gcs_bucket "$@"' _ {} \
            "$gcs_exists" "$gcs_readable" "$gcs_writable" \
            < "$gcs_candidates" 2>/dev/null
        unset -f _check_gcs_bucket
    fi

    if [ "$azure_verified_count" -gt 0 ]; then
        info "Testing explicitly approved, referenced Azure Blob accounts..."
        _check_azure_bucket() {
            local name="$1" exists_file="$2" readable_file="$3"
            cloud_resource_allowed "azure:$name" || return 0
            local url="https://${name}.blob.core.windows.net" rc container body_file crc
            rc=$(authorized_cloud_curl "azure:$name" -sS --max-time 8 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || printf '000')
            case "$rc" in 200|400|401|403) printf '%s\n' "$url" >> "$exists_file" ;; *) return 0 ;; esac
            for container in public '$web' assets backup data uploads media; do
                body_file=$(mktemp)
                crc=$(authorized_cloud_curl "azure:$name" -sS --max-time 5 -o "$body_file" -w '%{http_code}' \
                    "${url}/${container}?restype=container&comp=list" 2>/dev/null || printf '000')
                if [ "$crc" = 200 ] && grep -q '<EnumerationResults' "$body_file"; then
                    printf '%s/%s?restype=container&comp=list\n' "$url" "$container" >> "$readable_file"
                fi
                rm -f "$body_file"
            done
        }
        export -f _check_azure_bucket
        local azure_threads=$(( CLOUD_ENUM_THREADS / 2 ))
        [ "$azure_threads" -lt 1 ] && azure_threads=1
        xargs -r -P "$azure_threads" -I {} \
            bash -c 'set -uo pipefail; _check_azure_bucket "$@"' _ {} \
            "$az_exists" "$az_readable" < "$azure_candidates" 2>/dev/null
        unset -f _check_azure_bucket
    fi

    if [ "$verified_count" -eq 0 ]; then
        warn "No referenced cloud resources had exact provider/resource approval; no provider probes were launched."
    fi

    # cloud_enum mutates globally unique names and cannot enforce ownership before
    # probing, so it is intentionally not executed automatically.
    if check_command "cloud_enum"; then
        info "cloud_enum detected but skipped: automatic mutations cannot be ownership-gated safely."
    fi

    sort -u -o "$s3_exists" "$s3_exists"; sort -u -o "$s3_readable" "$s3_readable"; sort -u -o "$s3_writable" "$s3_writable"
    sort -u -o "$gcs_exists" "$gcs_exists"; sort -u -o "$gcs_readable" "$gcs_readable"; sort -u -o "$gcs_writable" "$gcs_writable"
    sort -u -o "$az_exists" "$az_exists"; sort -u -o "$az_readable" "$az_readable"

    local exposed_file="$cdir/exposed/all-exposed-buckets.txt"
    local critical_file="$cdir/exposed/critical-writable.txt"
    cat "$s3_readable" "$gcs_readable" "$az_readable" 2>/dev/null | sort -u > "$exposed_file"
    cat "$s3_writable" "$gcs_writable" 2>/dev/null | sort -u > "$critical_file"

    # Provider endpoints are outside TARGET's hostname boundary. Keep them in the
    # cloud report but do not feed them into generic URL scanning phases.
    : > "$cdir/exposed/cloud-urls-for-phase5.txt"

    local total_exposed total_writable
    total_exposed=$(count_lines "$exposed_file")
    total_writable=$(count_lines "$critical_file")
    if [ "$total_writable" -gt 0 ]; then
        error "🚨 CRITICAL: $total_writable publicly writable bucket(s) found → $critical_file"
        notify "🚨 CRITICAL — Writable Buckets" \
            "*${total_writable}* publicly writable cloud bucket(s) found.\nReview: \`${critical_file}\`"
    fi
    if [ "$total_exposed" -gt 0 ]; then
        warn "☁️  $total_exposed publicly readable bucket(s) found → $exposed_file"
        notify "☁️ Cloud Storage Exposed" \
            "*${total_exposed}* publicly readable bucket(s) found.\nSee: \`${exposed_file}\`"
    else
        success "No ownership-corroborated public cloud storage exposure found."
    fi

    rm -f "$token_file" "$candidates_file" "$s3_candidates" "$gcs_candidates" "$azure_candidates"
    merge_phase_backup "$cdir"
    success "Phase 2.5 complete!"
    polite_sleep
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3: Live Web Service Probing
# ─────────────────────────────────────────────────────────────────────────────
phase3_probing() {
    authorization_allowed enumeration || { info "phase3_probing: skipped by authorization policy"; return 0; }
    phase_done 3 && { polite_sleep; return 0; }
    print_phase "🌐 PHASE 3: LIVE WEB SERVICE PROBING"

    local p2dir="$OUTPUT_DIR/phase2-validation"
    local p3dir="$OUTPUT_DIR/phase3-probing"
    local phase_errors=0

    if [ ! -s "$p2dir/valid-subdomains.txt" ]; then
        error "No valid subdomains from Phase 2. Skipping Phase 3."
        return 1
    fi
    backup_phase_outputs "$p3dir"

    info "Probing for live web hosts..."
    : > "$p3dir/live-hosts.txt"
    if ! authorized_run enumeration list "$p2dir/valid-subdomains.txt" httpx-toolkit -l @AUTHORIZED_INPUT@ -silent -random-agent \
        -timeout 15 -retries 2 -rl 10 -o "$p3dir/live-hosts.txt" 2>/dev/null; then
        warn "Basic HTTP probing failed; partial output was preserved."
        phase_errors=$(( phase_errors + 1 ))
    fi
    success "Live web hosts: $(count_lines "$p3dir/live-hosts.txt")"

    info "Collecting detailed metadata..."
    : > "$p3dir/live-hosts-detailed.txt"
    if ! authorized_run enumeration list "$p2dir/valid-subdomains.txt" httpx-toolkit -l @AUTHORIZED_INPUT@ \
        -title -status-code -tech-detect -content-length -web-server \
        -random-agent -timeout 15 -retries 2 \
        -threads 10 -rl 10 -o "$p3dir/live-hosts-detailed.txt" 2>/dev/null; then
        warn "Detailed HTTP probing failed; partial output was preserved."
        phase_errors=$(( phase_errors + 1 ))
    fi

    info "Categorizing hosts by HTTP status code..."
    sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,3})*)?[mGKHF]//g" \
        "$p3dir/live-hosts-detailed.txt" > "$p3dir/clean-hosts.txt"
    grep -E '\[([0-9]+,)*200\]' "$p3dir/clean-hosts.txt" | awk '{print $1}' > "$p3dir/status-200.txt" || true
    grep -E '\[([0-9]+,)*403\]' "$p3dir/clean-hosts.txt" | awk '{print $1}' > "$p3dir/status-403.txt" || true
    grep -E '\[([0-9]+,)*401\]' "$p3dir/clean-hosts.txt" | awk '{print $1}' > "$p3dir/status-401.txt" || true
    grep -E '\[([0-9]+,)*(301|302|307|308)\]' "$p3dir/clean-hosts.txt" | awk '{print $1}' > "$p3dir/status-redirects.txt" || true
    grep -E '\[([0-9]+,)*500\]' "$p3dir/clean-hosts.txt" | awk '{print $1}' > "$p3dir/status-500.txt" || true

    info "Status breakdown:"
    echo "  200 OK       : $(count_lines "$p3dir/status-200.txt")"
    echo "  403 Forbidden: $(count_lines "$p3dir/status-403.txt")"
    echo "  401 Unauth   : $(count_lines "$p3dir/status-401.txt")"
    echo "  Redirects    : $(count_lines "$p3dir/status-redirects.txt")"
    echo "  500 Errors   : $(count_lines "$p3dir/status-500.txt")"

    : > "$p3dir/discovered-vhosts.txt"
    : > "$p3dir/vhost-findings.txt"
    if [ "$RUN_VHOST_DISCOVERY" = true ] && check_command "ffuf" && check_command "dig" \
       && [ -s "$SECLISTS/Discovery/DNS/subdomains-top1million-5000.txt" ] \
       && [ -r "$SECLISTS/Discovery/DNS/subdomains-top1million-5000.txt" ]; then
        info "Running virtual host discovery via Host header injection (top 5 live hosts)..."
        local vhost_count=0 vhost_ffuf_log="$p3dir/.vhost-ffuf-errors.log"
        : > "$vhost_ffuf_log"
        while IFS= read -r host && [ "$vhost_count" -lt 5 ]; do
            local safe_name scheme hostname target_ip output_json ffuf_rc
            safe_name=$(safe_artifact_name "$host")
            scheme=$(printf '%s' "$host" | grep -oE '^https?' || true)
            hostname=$(printf '%s' "$host" | sed -E 's|https?://||; s|/.*||; s|:[0-9]+$||')
            target_ip=$(authorized_run enumeration host "$hostname" dig +short @AUTHORIZED_INPUT@ A 2>/dev/null \
                | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
            if [ -z "$target_ip" ] || [ -z "$scheme" ]; then
                warn "  Could not resolve or parse $host — skipping vhost scan."
                vhost_count=$(( vhost_count + 1 ))
                continue
            fi

            output_json="$OUTPUT_DIR/phase11-fuzzing/vhosts/vhost-$safe_name.json"
            info "  Vhost fuzzing: $hostname ($target_ip)"
            authorized_run validation host "${scheme}://${target_ip}/" timeout --signal=TERM --kill-after=10 "$FFUF_TIMEOUT" \
                ffuf -u @AUTHORIZED_INPUT@ -H "Host: FUZZ.$TARGET" \
                -w "$SECLISTS/Discovery/DNS/subdomains-top1million-5000.txt" \
                -mc 200,301,302,401,403 -t "$FFUF_THREADS" -rate 50 \
                -o "$output_json" -of json -fs 0 -ac -s \
                >/dev/null 2>>"$vhost_ffuf_log"
            ffuf_rc=$?
            if [ "$ffuf_rc" -eq 124 ] || [ "$ffuf_rc" -eq 137 ]; then
                warn "  Vhost ffuf timed out for $hostname; partial JSON was preserved."
                phase_errors=$(( phase_errors + 1 ))
            elif [ "$ffuf_rc" -ne 0 ]; then
                warn "  Vhost ffuf failed for $hostname with code $ffuf_rc."
                phase_errors=$(( phase_errors + 1 ))
            fi

            if [ -s "$output_json" ]; then
                jq -r '.results[]?.input.FUZZ // empty' "$output_json" 2>/dev/null \
                    | sed "s/$/.$TARGET/" | in_scope >> "$p3dir/discovered-vhosts.txt" || true
                jq -r --arg scheme "$scheme" --arg ip "$target_ip" --arg target "$TARGET" \
                    '.results[]? | select(.input.FUZZ != null) | "\($scheme)://\($ip)/  Host: \(.input.FUZZ).\($target)  Status: \(.status)  Length: \(.length)"' \
                    "$output_json" 2>/dev/null >> "$p3dir/vhost-findings.txt" || true
            fi
            vhost_count=$(( vhost_count + 1 ))
        done < "$p3dir/status-200.txt"
        sort -u -o "$p3dir/discovered-vhosts.txt" "$p3dir/discovered-vhosts.txt"
        sort -u -o "$p3dir/vhost-findings.txt" "$p3dir/vhost-findings.txt"
        success "Virtual host discovery complete: $(count_lines "$p3dir/discovered-vhosts.txt") candidate vhost(s)"
        [ -s "$vhost_ffuf_log" ] && info "vhost ffuf stderr preserved at: $vhost_ffuf_log"
    fi

    merge_phase_backup "$p3dir"
    if [ "$phase_errors" -gt 0 ]; then
        warn "Phase 3 completed with $phase_errors error(s); checkpoint was not advanced."
        return 1
    fi

    success "Phase 3 complete!"
    save_checkpoint 3
    polite_sleep
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4: Port Scanning
# ─────────────────────────────────────────────────────────────────────────────
phase4_portscan() {
    authorization_allowed enumeration || { info "phase4_portscan: skipped by authorization policy"; return 0; }
    phase_done 4 && { polite_sleep; return 0; }
    print_phase "🔌 PHASE 4: PORT SCANNING"

    if [ "$RUN_PORT_SCAN" = false ]; then
        info "Port scanning skipped (mode: $SCAN_MODE)."
        save_checkpoint 4
        polite_sleep
        return 0
    fi

    local p2dir="$OUTPUT_DIR/phase2-validation"
    local p3dir="$OUTPUT_DIR/phase3-probing"
    local p4dir="$OUTPUT_DIR/phase4-portscan"
    local phase_errors=0

    if [ ! -s "$p2dir/valid-subdomains.txt" ]; then
        warn "No valid subdomains for port scanning. Skipping Phase 4."
        save_checkpoint 4
        polite_sleep
        return 0
    fi
    backup_phase_outputs "$p4dir"

    # 4.1 Scan top 1000 ports with Naabu
    info "Scanning top 1000 ports with Naabu..."
    : > "$p4dir/open-ports.txt"
    if ! authorized_run enumeration list "$p2dir/valid-subdomains.txt" naabu -list @AUTHORIZED_INPUT@ \
        -top-ports 1000 \
        -silent \
        -rate 300 \
        -o "$p4dir/open-ports.txt" 2>"$p4dir/naabu-error.log"; then
        warn "Naabu failed; see $p4dir/naabu-error.log. Partial output was preserved."
        phase_errors=$(( phase_errors + 1 ))
    fi
    success "Open ports discovered: $(count_lines "$p4dir/open-ports.txt")"

    # 4.2 Probe non-standard ports for web services
    : > "$p4dir/services-on-ports.txt"
    if [ -s "$p4dir/open-ports.txt" ]; then
        info "Probing open ports for HTTP/HTTPS services..."
        if ! authorized_run enumeration list "$p4dir/open-ports.txt" httpx-toolkit -l @AUTHORIZED_INPUT@ \
            -silent \
            -random-agent \
            -rl 50 \
            -o "$p4dir/services-on-ports.txt" 2>"$p4dir/httpx-ports-error.log"; then
            warn "httpx-toolkit failed while probing open ports; see $p4dir/httpx-ports-error.log."
            phase_errors=$(( phase_errors + 1 ))
        fi

        # Merge into live-hosts (anew is more efficient, falls back to sort -u)
        if [ -s "$p4dir/services-on-ports.txt" ]; then
            if check_command "anew"; then
                anew "$p3dir/live-hosts.txt" < "$p4dir/services-on-ports.txt" > /dev/null
            else
                cat "$p3dir/live-hosts.txt" "$p4dir/services-on-ports.txt" 2>/dev/null \
                    | sort -u > "$p3dir/live-hosts-tmp.txt"
                mv -f "$p3dir/live-hosts-tmp.txt" "$p3dir/live-hosts.txt"
            fi
        fi
        success "Additional web services on non-standard ports: $(count_lines "$p4dir/services-on-ports.txt")"
    fi

    merge_phase_backup "$p4dir"
    success "Phase 4 complete!"
    if [ "$phase_errors" -gt 0 ]; then
        warn "Phase 4 completed with $phase_errors error(s); checkpoint was not advanced."
        return 1
    fi
    save_checkpoint 4
    polite_sleep
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5: URL Discovery & Crawling
# ─────────────────────────────────────────────────────────────────────────────
phase5_url_discovery() {
    authorization_allowed enumeration || { info "phase5_url_discovery: skipped by authorization policy"; return 0; }
    phase_done 5 && { polite_sleep; return 0; }
    print_phase "🔗 PHASE 5: URL DISCOVERY & CRAWLING"

    local p2dir="$OUTPUT_DIR/phase2-validation"
    local p3dir="$OUTPUT_DIR/phase3-probing"
    local p5dir="$OUTPUT_DIR/phase5-urls"
    local phase_errors=0
    backup_phase_outputs "$p5dir"

    # Always initialize the main Phase 5 outputs so later phases/reporting do not
    # fail when Phase 3 found no live hosts or a passive source is unavailable.
    : > "$p5dir/katana-urls.txt"
    : > "$p5dir/hakrawler-urls.txt"
    : > "$p5dir/cariddi-urls.txt"
    : > "$p5dir/wayback-urls.txt"
    : > "$p5dir/gau-urls.txt"
    : > "$p5dir/all-urls-raw.txt"
    : > "$p5dir/all-urls.txt"
    : > "$p5dir/all-urls-injectable.txt"

    # 5.1 Active crawling with Katana (JS-aware, finds modern SPA endpoints)
    if [ -s "$p3dir/live-hosts.txt" ]; then
        info "Crawling with Katana (depth 3, JS-aware)..."
        if ! authorized_run enumeration list "$p3dir/live-hosts.txt" katana -list @AUTHORIZED_INPUT@ \
            -depth "$KATANA_DEPTH" \
            -js-crawl \
            -known-files all \
            -silent \
            -rl 50 \
            -o "$p5dir/katana-urls.txt" 2>"$p5dir/katana-error.log"; then
            warn "Katana failed; see $p5dir/katana-error.log. Partial output was preserved."
            phase_errors=$(( phase_errors + 1 ))
        fi
        success "Katana: $(count_lines "$p5dir/katana-urls.txt") URLs"
    else
        touch "$p5dir/katana-urls.txt"
    fi

    # 5.2 Hakrawler — lightweight spider for additional coverage
    if check_command "hakrawler" && [ -s "$p3dir/live-hosts.txt" ]; then
        info "Running Hakrawler..."
        cat "$p3dir/live-hosts.txt" \
            | authorized_run enumeration stream "" hakrawler -d 2 -timeout 10 -u 2>/dev/null \
            > "$p5dir/hakrawler-urls.txt"
        success "Hakrawler: $(count_lines "$p5dir/hakrawler-urls.txt") URLs"
    else
        touch "$p5dir/hakrawler-urls.txt"
    fi

    # 5.3 Cariddi — full crawler with built-in secrets/endpoint detection
    if check_command "cariddi" && [ -s "$p3dir/live-hosts.txt" ]; then
        info "Running Cariddi (secrets + endpoint mode)..."
        cat "$p3dir/live-hosts.txt" \
            | authorized_run enumeration stream "" cariddi -s -e -intensive 1 \
            > "$p5dir/cariddi-urls.txt" 2>/dev/null
        success "Cariddi: $(count_lines "$p5dir/cariddi-urls.txt") items"
    else
        touch "$p5dir/cariddi-urls.txt"
    fi

    # 5.4 Historical URL mining — Waybackurls
    if [ -s "$p3dir/live-hosts.txt" ]; then
        info "Mining Wayback Machine for historical URLs..."
        if ! authorized_run passive stream "" waybackurls < "$p3dir/live-hosts.txt" \
            > "$p5dir/wayback-urls.txt" 2>"$p5dir/wayback-error.log"; then
            warn "Waybackurls failed; see $p5dir/wayback-error.log. Partial output was preserved."
            phase_errors=$(( phase_errors + 1 ))
        fi
    else
        info "No live hosts for Waybackurls; output will be empty."
        : > "$p5dir/wayback-urls.txt"
    fi
    success "Waybackurls: $(count_lines "$p5dir/wayback-urls.txt") URLs"

    # 5.5 Historical URL mining — GAU (Common Crawl + Wayback + OTX)
    if [ -s "$p2dir/valid-subdomains.txt" ]; then
        info "Running GAU for additional historical URLs..."
        if ! authorized_run passive stream "" timeout 5m gau --threads "$GAU_THREADS" < "$p2dir/valid-subdomains.txt" \
            > "$p5dir/gau-urls.txt" 2>"$p5dir/gau-error.log"; then
            warn "GAU failed or timed out; see $p5dir/gau-error.log. Partial output was preserved."
            phase_errors=$(( phase_errors + 1 ))
        fi
    else
        info "No valid subdomains for GAU; output will be empty."
        : > "$p5dir/gau-urls.txt"
    fi
    success "GAU: $(count_lines "$p5dir/gau-urls.txt") URLs"

    # 5.6 Merge all URL sources — explicit list prevents self-inclusion bug.
    # NOTE: this produces the RAW corpus.  Wayback/GAU dump every path a domain
    # ever served — dead links, 404s, third-party junk, and infinite querystring
    # permutations — so the raw set is mostly noise.  We refine it in 5.6b before
    # anything downstream (categorisation, params, gf, vuln phases) consumes it.
    info "Merging and deduplicating all URL sources..."
    local cloud_p5_feed="$OUTPUT_DIR/phase2.5-cloud/exposed/cloud-urls-for-phase5.txt"
    cat "$p5dir/katana-urls.txt" \
        "$p5dir/hakrawler-urls.txt" \
        "$p5dir/cariddi-urls.txt" \
        "$p5dir/wayback-urls.txt" \
        "$p5dir/gau-urls.txt" \
        "${cloud_p5_feed:-/dev/null}" \
        2>/dev/null | sort -u > "$p5dir/all-urls-raw.txt"
    local raw_count
    raw_count=$(count_lines "$p5dir/all-urls-raw.txt")
    success "Raw merged URLs: $raw_count"

    # ── 5.6b Refine the corpus — DUAL OUTPUT ──────────────────────────────────
    # The refinement produces TWO corpora because different consumers need
    # different inputs:
    #
    #   all-urls.txt            (CLEAN)  scoped → param-collapsed → liveness.
    #                                    For categorisation, parameter mining,
    #                                    reporting, screenshots.  Low noise.
    #
    #   all-urls-injectable.txt (FULL)   scoped → parametered-only.  NOT collapsed,
    #                                    NOT liveness-filtered.  Every distinct
    #                                    param=value pair is preserved because
    #                                    injection testing (gf, sqlmap, dalfox,
    #                                    IDOR) needs concrete distinct values and
    #                                    must see endpoints whose BASELINE status
    #                                    is 404/500/etc (those are often the most
    #                                    injectable).  Collapsing or liveness-
    #                                    gating this set is what starved SQLi/XSS.
    #
    # Rationale for the split: param-collapse and a fixed liveness whitelist are
    # correct for building a tidy endpoint inventory, but actively harmful for
    # vuln testing — ?id=1/?id=2/?id=947 collapse to one URL, and an endpoint
    # that 500s on a probe gets dropped though it is a prime SQLi target.  We
    # therefore optimise each corpus for its job instead of forcing one to serve
    # both.
    info "Refining URL corpus (scope → dedup → liveness; + full injectable set)..."

    # Stage 1 — SCOPE (shared by both corpora).
    local scoped="$p5dir/.urls-scoped.txt"
    if ! in_scope < "$p5dir/all-urls-raw.txt" | sort -u > "$scoped"; then
        : > "$scoped"
        error "Scope filtering failed; raw URLs will not be used."
        return 1
    fi
    info "  Scope filter: $(count_lines "$scoped") in-scope (from $raw_count)"

    # ── FULL injectable corpus: every scoped URL that carries a query parameter,
    #    de-duplicated EXACTLY (not by signature) so distinct values survive.
    #    This is the source of truth for Phase 9 injection tools and Phase 8 JS.
    local injectable="$p5dir/all-urls-injectable.txt"
    grep -E '\?[^[:space:]]*=' "$scoped" 2>/dev/null | sort -u > "$injectable" || touch "$injectable"
    info "  Injectable corpus (parametered, full-value): $(count_lines "$injectable") URLs"

    # Stage 2 — PARAMETER COLLAPSE (CLEAN corpus only).  ?id=1/?id=2/?id=3 → one
    # representative endpoint.  This drives the tidy inventory, not vuln testing.
    local collapsed="$p5dir/.urls-collapsed.txt"
    awk '
        {
            url = $0
            sig = url
            gsub(/=[^&]*/, "=", sig)   # blank every query value for signature
            if (!(sig in seen)) {
                seen[sig] = 1
                print url
            }
        }
    ' "$scoped" > "$collapsed"
    info "  Param-collapse: $(count_lines "$collapsed") unique endpoints (from $(count_lines "$scoped"))"

    # Stage 3 — LIVENESS (CLEAN corpus only).  Probe collapsed set; keep live.
    local clean="$p5dir/all-urls.txt"
    if [ -s "$collapsed" ] && check_command "httpx-toolkit"; then
        if ! authorized_run enumeration list "$collapsed" httpx-toolkit -l @AUTHORIZED_INPUT@ \
            -silent \
            -mc 200,201,202,204,301,302,307,308,401,403,405,500 \
            -random-agent \
            -rl 50 \
            -o "$clean" 2>/dev/null; then
            : > "$clean"
            error "Authorized URL probing failed; input will not be restored."
            return 1
        fi
    else
        warn "  httpx-toolkit unavailable — skipping liveness validation (corpus may contain dead URLs)."
        in_scope < "$collapsed" > "$clean" || { : > "$clean"; return 1; }
    fi

    # Provider resources never bypass host policy through a stored cloud feed.
    sort -u -o "$clean" "$clean"

    success "Refined URL corpus: $(count_lines "$clean") clean endpoints / $(count_lines "$injectable") injectable URLs (from $raw_count raw)"

    # NOTE: $scoped is intentionally retained until after JS extraction below,
    # because JS discovery must run on the PRE-collapse, PRE-liveness set so that
    # cache-busted (app.js?v=HASH) and CDN-served JS are not dropped before the
    # dedicated JS validation in 5.8.  It is removed at the end of 5.8.

    # 5.7 Categorize URLs by content type — CLEAN corpus for the tidy categories.
    info "Categorizing URLs by type..."

    grep -iE '\.(js|json|xml|config|yml|yaml|env|bak|backup|sql|db|log)(\?.*)?$' \
        "$p5dir/all-urls.txt" > "$p5dir/interesting-files.txt" 2>/dev/null || touch "$p5dir/interesting-files.txt"

    # Tighter API pattern — matches path segments, not just keywords anywhere in URL
    grep -iE '(/api/|/v1/|/v2/|/v3/|graphql|/rest/)' \
        "$p5dir/all-urls.txt" > "$p5dir/api-endpoints.txt" 2>/dev/null || touch "$p5dir/api-endpoints.txt"

    grep -iE '(admin|login|dashboard|upload|config|backup|dev|staging|test|debug|manage|panel)' \
        "$p5dir/all-urls.txt" > "$p5dir/sensitive-endpoints.txt" 2>/dev/null || touch "$p5dir/sensitive-endpoints.txt"

    # 5.8 JS discovery + validation.
    # Source from the SCOPED set (pre-collapse/pre-liveness) so no live JS is lost
    # upstream.  De-dup .js URLs by path (ignoring cache-buster query) to avoid
    # validating the same file 100x, but KEEP one representative per distinct path
    # INCLUDING its query so conditional/CDN serving still resolves.
    grep -iE '\.js(\?.*)?$' "$scoped" 2>/dev/null \
        | awk '{ p=$0; sub(/\?.*/,"",p); if(!(p in s)){s[p]=1; print} }' \
        > "$p5dir/all-js-files.txt" 2>/dev/null || touch "$p5dir/all-js-files.txt"
    info "  Candidate JS files (pre-validation): $(count_lines "$p5dir/all-js-files.txt")"

    # Validate JS seeds without enabling redirects to a different destination.
    if [ -s "$p5dir/all-js-files.txt" ]; then
        if check_command "httpx-toolkit"; then
            if ! authorized_run enumeration list "$p5dir/all-js-files.txt" httpx-toolkit -l @AUTHORIZED_INPUT@ \
                -silent -mc 200,304 \
                -random-agent \
                -rl 50 \
                -o "$p5dir/live-js-files.txt" 2>/dev/null; then
                : > "$p5dir/live-js-files.txt"
                error "Authorized JS probing failed; candidates will not be restored."
                return 1
            fi
        else
            in_scope < "$p5dir/all-js-files.txt" > "$p5dir/live-js-files.txt" \
                || { : > "$p5dir/live-js-files.txt"; return 1; }
        fi
        success "Live JS files: $(count_lines "$p5dir/live-js-files.txt")"
    else
        touch "$p5dir/live-js-files.txt"
        info "No .js URLs discovered in corpus."
    fi

    rm -f "$scoped" "$collapsed"

    # 5.9 GF pattern matching — tomnomnom/gf gives higher-signal URL filtering.
    # Runs on the FULL injectable corpus (all distinct param=value pairs), NOT
    # the collapsed clean corpus — gf feeds the injection tools in Phase 9, which
    # need every distinct value, not one representative per endpoint signature.
    if check_command "gf"; then
        local gf_source="$p5dir/all-urls-injectable.txt"
        [ -s "$gf_source" ] || gf_source="$p5dir/all-urls.txt"   # fallback
        info "Running GF pattern matching on injectable corpus ($(count_lines "$gf_source") URLs)..."
        for pattern in xss sqli ssrf redirect lfi idor; do
            # Check if the gf pattern is actually installed before running
            if gf -list 2>/dev/null | grep -q "^$pattern$"; then
                gf "$pattern" "$gf_source" \
                    > "$p5dir/gf-$pattern.txt" 2>/dev/null || touch "$p5dir/gf-$pattern.txt"
                local cnt
                cnt=$(count_lines "$p5dir/gf-$pattern.txt")
                [ "$cnt" -gt 0 ] && info "  gf-$pattern: $cnt URLs"
            else
                warn "  gf pattern '$pattern' not installed — skipping."
                touch "$p5dir/gf-$pattern.txt"
            fi
        done
        success "GF pattern matching complete"
    else
        warn "gf not found — install tomnomnom/gf for higher-accuracy URL filtering."
    fi

    merge_phase_backup "$p5dir"
    success "Phase 5 complete!"
    if [ "$phase_errors" -gt 0 ]; then
        warn "Phase 5 completed with $phase_errors error(s); checkpoint was not advanced."
        return 1
    fi
    save_checkpoint 5
    polite_sleep
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6: Parameter Discovery
# ─────────────────────────────────────────────────────────────────────────────
phase6_parameters() {
    authorization_allowed enumeration || { info "phase6_parameters: skipped by authorization policy"; return 0; }
    phase_done 6 && { polite_sleep; return 0; }
    print_phase "📊 PHASE 6: PARAMETER DISCOVERY"

    local p5dir="$OUTPUT_DIR/phase5-urls"
    local p6dir="$OUTPUT_DIR/phase6-parameters"
    local p3dir="$OUTPUT_DIR/phase3-probing"
    local phase_errors=0
    backup_phase_outputs "$p6dir"

    : > "$p6dir/parameters.txt"
    : > "$p6dir/arjun-all-params.txt"

    # 6.1 Passive parameter extraction with Unfurl
    if [ -s "$p5dir/all-urls.txt" ]; then
        info "Extracting known parameters from URL corpus with Unfurl..."
        if ! unfurl keys < "$p5dir/all-urls.txt" 2>"$p6dir/unfurl-error.log" \
            | sort -u > "$p6dir/parameters.txt"; then
            warn "Unfurl failed; see $p6dir/unfurl-error.log."
            phase_errors=$(( phase_errors + 1 ))
        fi
    else
        warn "No Phase 5 URL corpus found; passive parameter extraction will be empty."
    fi
    success "Unique parameter names: $(count_lines "$p6dir/parameters.txt")"

    # 6.2 Active parameter discovery with Arjun (configurable limit)
    if [ "$RUN_PARAM_DISCOVERY" = false ]; then
        info "Active parameter discovery skipped (mode: $SCAN_MODE)."
    elif [ -s "$p3dir/status-200.txt" ]; then
        info "Running Arjun on up to $MAX_ARJUN_HOSTS hosts..."
        local count=0
        while IFS= read -r url && [ "$count" -lt "$MAX_ARJUN_HOSTS" ]; do
            info "  Arjun → $url"
            if ! authorized_run validation host "$url" arjun -u @AUTHORIZED_INPUT@ \
                -t "$ARJUN_THREADS" \
                -oT "$p6dir/arjun-params-$count.txt" \
                -d 500 2>>"$p6dir/arjun-error.log"; then
                warn "  Arjun failed for $url; see $p6dir/arjun-error.log."
                phase_errors=$(( phase_errors + 1 ))
            fi
            count=$(( count + 1 ))
        done < "$p3dir/status-200.txt"

        cat "$p6dir"/arjun-params-*.txt 2>/dev/null \
            | sort -u > "$p6dir/arjun-all-params.txt"
        success "Arjun scanned $count hosts"
    else
        warn "No status-200 hosts for Arjun."
    fi

    merge_phase_backup "$p6dir"
    success "Phase 6 complete!"
    if [ "$phase_errors" -gt 0 ]; then
        warn "Phase 6 completed with $phase_errors error(s); checkpoint was not advanced."
        return 1
    fi
    save_checkpoint 6
    polite_sleep
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6b: Asset Scoring & Prioritization
# ─────────────────────────────────────────────────────────────────────────────
phase_asset_scoring() {
    # NOTE: No checkpoint guard — this phase is a fast local computation (no
    # network I/O) so it always re-runs, guaranteeing scores reflect the latest
    # data even on resume.  Runs in <2s on typical scan outputs.
    print_phase "📊 PHASE 6b: ASSET SCORING & PRIORITIZATION"

    if [ "$RUN_ASSET_SCORING" = false ]; then
        info "Asset scoring skipped (mode: $SCAN_MODE)."
        return
    fi

    local p3dir="$OUTPUT_DIR/phase3-probing"
    local p4dir="$OUTPUT_DIR/phase4-portscan"
    local p5dir="$OUTPUT_DIR/phase5-urls"
    local p6dir="$OUTPUT_DIR/phase6-parameters"
    local score_dir="$OUTPUT_DIR/asset-scoring"

    if [ ! -s "$p3dir/live-hosts.txt" ]; then
        warn "No live hosts from Phase 3. Skipping asset scoring."
        return
    fi

    # ── Build the host universe ──────────────────────────────────────────────
    # Normalize all live-host URLs to scheme://hostname (no trailing path/port
    # variations) so we can match against URL-based files consistently.
    info "Building host universe from live-hosts.txt..."
    local host_list="$score_dir/.host-universe.txt"
    sed -E 's|^(https?://[^/]+).*|\1|' "$p3dir/live-hosts.txt" \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u \
        | head -"$MAX_SCORE_HOSTS" > "$host_list"

    local total_hosts
    total_hosts=$(count_lines "$host_list")
    info "Scoring $total_hosts unique hosts..."

    # ── Prepare lookup files ─────────────────────────────────────────────────
    # Pre-lowercase all input files into temp copies so grep -c matches are
    # case-insensitive without paying per-host grep -i overhead.
    local tmp_dir="$score_dir/.tmp"
    mkdir -p "$tmp_dir"

    _lc_copy() {
        # Usage: _lc_copy <src> <dest>  — lowercases into dest, or touches empty
        if [ -s "$1" ]; then
            tr '[:upper:]' '[:lower:]' < "$1" > "$2"
        else
            : > "$2"
        fi
    }

    _lc_copy "$p3dir/status-200.txt"            "$tmp_dir/s200"
    _lc_copy "$p3dir/status-401.txt"            "$tmp_dir/s401"
    _lc_copy "$p3dir/status-403.txt"            "$tmp_dir/s403"
    _lc_copy "$p3dir/status-500.txt"            "$tmp_dir/s500"
    _lc_copy "$p3dir/clean-hosts.txt"           "$tmp_dir/detailed"
    _lc_copy "$p4dir/services-on-ports.txt"     "$tmp_dir/alt-ports"
    _lc_copy "$p5dir/api-endpoints.txt"         "$tmp_dir/apis"
    _lc_copy "$p5dir/sensitive-endpoints.txt"   "$tmp_dir/sensitive"
    _lc_copy "$p5dir/interesting-files.txt"     "$tmp_dir/interesting"
    _lc_copy "$p5dir/live-js-files.txt"         "$tmp_dir/jsfiles"

    # Merge all GF pattern matches into one file for counting
    local gf_merged="$tmp_dir/gf-all"
    : > "$gf_merged"
    for gf_file in "$p5dir"/gf-*.txt; do
        [ -s "$gf_file" ] && cat "$gf_file" >> "$gf_merged"
    done
    tr '[:upper:]' '[:lower:]' < "$gf_merged" > "$gf_merged.lc" && mv "$gf_merged.lc" "$gf_merged"

    # Merge all parameter files (passive + Arjun) — count unique params per host
    # Parameters from Unfurl are global (not per-host), so we go back to the
    # raw URL corpus and extract params per host directly.
    local param_source="$tmp_dir/url-params"
    if [ -s "$p5dir/all-urls.txt" ]; then
        tr '[:upper:]' '[:lower:]' < "$p5dir/all-urls.txt" > "$param_source"
    else
        : > "$param_source"
    fi

    # Tech keywords that boost score — common high-value/vuln-prone stacks
    local tech_keywords="wordpress|wp-content|jira|jenkins|drupal|tomcat|struts|coldfusion|phpmyadmin|weblogic|grafana|kibana|elasticsearch|solr|confluence|bitbucket|gitlab|sonarqube|spring-boot|actuator|swagger|openapi|graphql"

    # ── Score each host ──────────────────────────────────────────────────────
    local scored_file="$score_dir/scored-targets.txt"
    local summary_file="$score_dir/scoring-summary.txt"
    : > "$scored_file"
    : > "$summary_file"

    while IFS= read -r host; do
        local score=0
        local reasons=""

        # Extract just the hostname portion for matching inside URLs
        local hostname
        hostname=$(echo "$host" | sed -E 's|^https?://||')

        # ── Status code signals ──────────────────────────────────────────
        if grep -qF "$hostname" "$tmp_dir/s200" 2>/dev/null; then
            score=$((score + 5))
            reasons="${reasons}200:+5 "
        fi
        if grep -qF "$hostname" "$tmp_dir/s401" 2>/dev/null; then
            score=$((score + 15))
            reasons="${reasons}401:+15 "
        fi
        if grep -qF "$hostname" "$tmp_dir/s403" 2>/dev/null; then
            score=$((score + 15))
            reasons="${reasons}403:+15 "
        fi
        if grep -qF "$hostname" "$tmp_dir/s500" 2>/dev/null; then
            score=$((score + 20))
            reasons="${reasons}500:+20 "
        fi

        # ── Non-standard port services ───────────────────────────────────
        # BUG-12: grep -cF prints "0" AND exits 1 on zero matches.  The naive
        # `$(grep -cF ... || echo 0)` pattern captures TWO lines ("0\n0") because
        # grep already emitted "0" before exiting 1, then || fires echo 0 adding
        # a second line.  The subsequent `[ "$count" -gt 0 ]` then fails with
        # "integer expression expected".
        # Fix: brace-group the grep + fallback and pipe to head -1 so we always
        # take only the first output line regardless of which branch ran.
        local alt_port_count=0
        if [ -s "$tmp_dir/alt-ports" ]; then
            alt_port_count=$( { grep -cF "$hostname" "$tmp_dir/alt-ports" 2>/dev/null || echo 0; } | head -1)
        fi
        if [ "$alt_port_count" -gt 0 ]; then
            local pts=$((alt_port_count * 10))
            score=$((score + pts))
            reasons="${reasons}alt-ports(${alt_port_count}):+${pts} "
        fi

        # ── API endpoints ────────────────────────────────────────────────
        local api_count=0
        if [ -s "$tmp_dir/apis" ]; then
            api_count=$( { grep -cF "$hostname" "$tmp_dir/apis" 2>/dev/null || echo 0; } | head -1)
        fi
        if [ "$api_count" -gt 0 ]; then
            local pts=$((api_count * 3))
            score=$((score + pts))
            reasons="${reasons}apis(${api_count}):+${pts} "
        fi

        # ── Sensitive endpoints ──────────────────────────────────────────
        local sens_count=0
        if [ -s "$tmp_dir/sensitive" ]; then
            sens_count=$( { grep -cF "$hostname" "$tmp_dir/sensitive" 2>/dev/null || echo 0; } | head -1)
        fi
        if [ "$sens_count" -gt 0 ]; then
            local pts=$((sens_count * 5))
            score=$((score + pts))
            reasons="${reasons}sensitive(${sens_count}):+${pts} "
        fi

        # ── Interesting files (config/bak/env) ───────────────────────────
        local int_count=0
        if [ -s "$tmp_dir/interesting" ]; then
            int_count=$( { grep -cF "$hostname" "$tmp_dir/interesting" 2>/dev/null || echo 0; } | head -1)
        fi
        if [ "$int_count" -gt 0 ]; then
            local pts=$((int_count * 4))
            score=$((score + pts))
            reasons="${reasons}files(${int_count}):+${pts} "
        fi

        # ── GF pattern matches ───────────────────────────────────────────
        local gf_count=0
        if [ -s "$gf_merged" ]; then
            gf_count=$( { grep -cF "$hostname" "$gf_merged" 2>/dev/null || echo 0; } | head -1)
        fi
        if [ "$gf_count" -gt 0 ]; then
            local pts=$((gf_count * 2))
            score=$((score + pts))
            reasons="${reasons}gf-patterns(${gf_count}):+${pts} "
        fi

        # ── Live JS files ────────────────────────────────────────────────
        local js_count=0
        if [ -s "$tmp_dir/jsfiles" ]; then
            js_count=$( { grep -cF "$hostname" "$tmp_dir/jsfiles" 2>/dev/null || echo 0; } | head -1)
        fi
        if [ "$js_count" -gt 0 ]; then
            local pts=$((js_count * 2))
            score=$((score + pts))
            reasons="${reasons}js(${js_count}):+${pts} "
        fi

        # ── Parameters (from URL corpus) ─────────────────────────────────
        local param_count=0
        if [ -s "$param_source" ]; then
            # Count unique param keys in URLs matching this host
            param_count=$(grep -F "$hostname" "$param_source" 2>/dev/null \
                | grep -oE '[?&][a-zA-Z0-9_-]+=' \
                | sed 's/[?&]//;s/=$//' \
                | sort -u \
                | wc -l)
        fi
        if [ "$param_count" -gt 0 ]; then
            score=$((score + param_count))
            reasons="${reasons}params(${param_count}):+${param_count} "
        fi

        # ── Tech stack keywords ──────────────────────────────────────────
        if [ -s "$tmp_dir/detailed" ]; then
            local tech_match
            tech_match=$(grep -iF "$hostname" "$tmp_dir/detailed" 2>/dev/null \
                | grep -oiE "$tech_keywords" \
                | sort -u | head -5)
            if [ -n "$tech_match" ]; then
                # Award 10 points per unique tech keyword match (cap at 3)
                local tech_count
                tech_count=$(echo "$tech_match" | wc -l)
                [ "$tech_count" -gt 3 ] && tech_count=3
                local pts=$((tech_count * 10))
                local tech_list
                tech_list=$(echo "$tech_match" | tr '\n' ',' | sed 's/,$//')
                score=$((score + pts))
                reasons="${reasons}tech(${tech_list}):+${pts} "
            fi
        fi

        # ── Write results ────────────────────────────────────────────────
        # Pad score to 4 digits for clean sort alignment
        printf "%04d | %-60s | %s\n" "$score" "$reasons" "$host" >> "$scored_file"

        # Detailed summary for manual review
        if [ "$score" -gt 0 ]; then
            {
                echo "── $host ── score: $score"
                echo "   $reasons"
                echo ""
            } >> "$summary_file"
        fi

    done < "$host_list"

    # ── Sort by score descending ─────────────────────────────────────────────
    sort -t'|' -k1 -rn "$scored_file" -o "$scored_file"

    # ── Generate top-targets list (top 25%, minimum 5) ───────────────────────
    local top_count
    top_count=$(( total_hosts / 4 ))
    [ "$top_count" -lt 5 ] && top_count=5
    [ "$top_count" -gt "$total_hosts" ] && top_count="$total_hosts"

    head -"$top_count" "$scored_file" \
        | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/, "", $3); print $3}' \
        > "$score_dir/top-targets.txt"

    # ── Print summary ────────────────────────────────────────────────────────
    local max_score min_score avg_score
    max_score=$(head -1 "$scored_file" | awk -F'|' '{gsub(/^[ \t]+/, "", $1); print $1+0}')
    min_score=$(tail -1 "$scored_file" | awk -F'|' '{gsub(/^[ \t]+/, "", $1); print $1+0}')
    avg_score=$(awk -F'|' '{gsub(/^[ \t]+/, "", $1); sum += $1+0} END {if (NR>0) printf "%d", sum/NR; else print 0}' "$scored_file")

    info "Score distribution:"
    echo "  Hosts scored     : $total_hosts"
    echo "  Highest score    : $max_score"
    echo "  Lowest score     : $min_score"
    echo "  Average score    : $avg_score"
    echo "  Top targets (25%): $(count_lines "$score_dir/top-targets.txt")"
    echo ""

    # Show the top 10 for quick eyeball
    info "Top 10 targets by score:"
    head -10 "$scored_file" | while IFS= read -r line; do
        echo "  $line"
    done

    # ── Cleanup temp files ───────────────────────────────────────────────────
    rm -rf "$tmp_dir" "$host_list"

    success "Asset scoring complete! → $score_dir/"
    polite_sleep
}

# ─────────────────────────────────────────────────────────────────────────────
# _p7_report_skips <logfile> <scan_label>
# Parses Nuclei stderr for "[skipped]" lines that indicate a host was dropped
# due to hitting max-host-error.  Emits a warning for each skipped host so
# coverage gaps are visible in the run log rather than silently absent from
# findings.  The raw log is preserved in the phase7 output directory.
_p7_report_skips() {
    local logfile="$1" label="$2"
    [ -f "$logfile" ] || return
    # BUG-1 FIX: grep -c emits "0" AND exits 1 on zero matches, so the naive
    # `grep -c ... || echo 0` pattern captures two lines ("0\n0") which fails
    # the [ -gt 0 ] integer test below.  Brace-group the grep + fallback and
    # pipe to head -1 so we always take only the first output line regardless
    # of which branch ran.  (Same fix pattern as phase_asset_scoring.)
    local skipped
    skipped=$( { grep -c "\[skipped\]" "$logfile" 2>/dev/null || echo 0; } | head -1)
    if [ "$skipped" -gt 0 ]; then
        warn "$label: $skipped host(s) skipped due to error threshold — check $(basename "$logfile") for details"
        grep "\[skipped\]" "$logfile" | while IFS= read -r line; do
            warn "  → $line"
        done
    fi
}

# PHASE 7: Vulnerability Scanning (Nuclei)
# ─────────────────────────────────────────────────────────────────────────────
phase7_vulnerability_scanning() {
    authorization_allowed validation || { info "phase7_vulnerability_scanning: skipped by authorization policy"; return 0; }
    phase_done 7 && { polite_sleep; return; }
    print_phase "🛡️  PHASE 7: VULNERABILITY SCANNING (NUCLEI)"

    local p7dir="$OUTPUT_DIR/phase7-vulns"
    local p3dir="$OUTPUT_DIR/phase3-probing"
    local p5dir="$OUTPUT_DIR/phase5-urls"
    local phase_status=0

    if [ ! -s "$p3dir/live-hosts.txt" ]; then
        warn "No live hosts for Nuclei. Skipping Phase 7."
        # BUG-8 FIX: record checkpoint so resume correctly skips this phase,
        # and honour polite_sleep for consistency with all other skip paths.
        save_checkpoint 7
        polite_sleep
        return 0
    fi

    backup_phase_outputs "$p7dir"
    rm -f "$p7dir"/{all-findings.txt,all-findings.json,exposure-findings.txt,exposure-findings.json,critical-findings.txt,high-medium-findings.txt,cve-findings.txt,api-findings.txt,endpoint-findings.txt,js-exposure-findings.txt,scan1-nuclei.log,scan1-stats.json,scan2-nuclei.log,scan2-stats.json} 2>/dev/null || true

    # Optional template update — auto-updates if templates are older than 7 days
    local nuclei_stamp="$HOME/.nuclei-last-update"
    local needs_update=false
    if [ "$UPDATE_NUCLEI" = true ]; then
        needs_update=true
    elif [ ! -f "$nuclei_stamp" ]; then
        needs_update=true
        info "Nuclei templates have never been updated — auto-updating..."
    else
        local days_since
        days_since=$(( ( $(date +%s) - $(date -r "$nuclei_stamp" +%s) ) / 86400 ))
        if [ "$days_since" -ge 7 ]; then
            needs_update=true
            info "Nuclei templates are $days_since days old — auto-updating..."
        else
            info "Nuclei templates are up to date ($days_since days old). Use -u to force update."
        fi
    fi

    if [ "$needs_update" = true ]; then
        info "Updating Nuclei templates..."
        if authorized_run validation maintenance "" nuclei -ut 2>/dev/null; then
            touch "$nuclei_stamp"
            success "Nuclei templates updated."
        else
            warn "Nuclei template update failed; continuing with the installed templates."
            phase_status=1
        fi
    fi

    # UNSIGNED-TEMPLATE ADVISORY: nuclei emits
    #     [WRN] Loading N unsigned templates for scan. Use with caution.
    # at scan start whenever the template directory contains any .yaml that
    # isn't covered by the official signing key (custom templates, forks,
    # locally modified files).  The warning is informational from nuclei's
    # side — it loaded them anyway — but represents a real trust decision the
    # operator should make consciously.  We surface a one-time inventory so
    # Jonaski can audit which templates are unsigned and decide whether to
    # keep them.  Inventory is best-effort and won't fail the phase.
    local _nt_dir="$NUCLEI_TEMPLATES"
    if [ -d "$_nt_dir" ]; then
        # A template is considered "potentially unsigned" if it lives outside
        # the official numbered version directory and lacks the standard
        # "# digest:" signature footer that nuclei-templates ship with.
        # This is heuristic — nuclei's own verifier is authoritative — but
        # gives the operator a list to inspect.
        local _unsigned_list="$p7dir/.unsigned-templates.txt"
        find "$_nt_dir" -type f -name '*.yaml' -not -path '*/\.*' 2>/dev/null \
            | while IFS= read -r _tpl; do
                if ! grep -q '^# digest:' "$_tpl" 2>/dev/null; then
                    printf '%s\n' "$_tpl"
                fi
              done > "$_unsigned_list" 2>/dev/null
        local _unsigned_count
        _unsigned_count=$(count_lines "$_unsigned_list")
        if [ "$_unsigned_count" -gt 0 ]; then
            warn "Nuclei template inventory: $_unsigned_count potentially unsigned template(s) detected."
            warn "  These will trigger '[WRN] Loading N unsigned templates' from nuclei."
            warn "  Audit with: cat $_unsigned_list"
            warn "  If any are not yours, remove with: while read t; do rm -i \"\$t\"; done < $_unsigned_list"
        else
            rm -f "$_unsigned_list"
        fi
    fi

    # ── Build partitioned target lists ──────────────────────────────────────
    #
    # BUG-1/3 FIX: Previously a single flat list mixed live hosts with JS file
    # URLs, API endpoints, and sensitive paths, then fed the whole set to every
    # template — including host-level TLS/DNS/network templates that can never
    # match a deep URL.  We now build two lists:
    #
    #   host-level targets  — roots only (live-hosts.txt); used for scan 7.1
    #   url-level targets   — host roots + all URL feeds, deduped; used for
    #                         the exposure scan (7.2) which targets paths.
    #
    # This prevents template×target cross-product inflation and matches each
    # template class against the target surface it was designed for.

    local host_targets="$p7dir/.host-targets.txt"
    local combined_targets="$p7dir/.combined-targets.txt"

    # SCOPE FIX: Filter all target lists through in_scope so third-party CDN /
    # ad / analytics hosts (jsdelivr, googlesyndication, facebook,
    # googletagmanager, etc.) that leaked in via Phase 5 URL gathering are
    # excluded.  Scanning third-party infrastructure is out-of-scope for any
    # bug-bounty engagement against TARGET and can violate program rules,
    # provider ToS, or local computer-misuse statutes.

    # Host-level list: live roots only, scope-filtered
    in_scope < "$p3dir/live-hosts.txt" 2>/dev/null | sort -u > "$host_targets"

    # Combined list: roots + URL feeds (for path-aware exposure templates),
    # scope-filtered before dedup.
    {
        cat "$p3dir/live-hosts.txt"
        [ -s "$p5dir/sensitive-endpoints.txt" ] && cat "$p5dir/sensitive-endpoints.txt"
        [ -s "$p5dir/live-js-files.txt" ]       && cat "$p5dir/live-js-files.txt"
        [ -s "$p5dir/api-endpoints.txt" ]        && cat "$p5dir/api-endpoints.txt"
    } 2>/dev/null | in_scope | sort -u > "$combined_targets"

    # Report dropped count for visibility — helps confirm scope filter is
    # doing its job (or flag a misconfigured TARGET if everything is dropped).
    local _raw_host_count _raw_url_count _dropped_hosts _dropped_urls
    _raw_host_count=$(count_lines "$p3dir/live-hosts.txt")
    # Guard each optional file with [ -s ] (mirroring the combined_targets block
    # above) so a missing Phase 5 category file cannot make `cat` fail.  The
    # previous version appended the path unconditionally via ${p5dir:+...} and
    # relied on `|| echo 0`, which — when cat failed on an absent file — printed
    # wc's count AND an extra "0" on a second line.  The multi-line value then
    # broke the $(( ... )) arithmetic on the next lines:
    #   line: 9\n0: syntax error in expression (error token is "0")
    # Phase 5 refinement (5.6b) can now legitimately yield empty/absent category
    # files, which is why this began crashing.  Build the count from a guarded
    # group with a single, deterministic output.
    _raw_url_count=$( {
        cat "$p3dir/live-hosts.txt"
        [ -s "$p5dir/sensitive-endpoints.txt" ] && cat "$p5dir/sensitive-endpoints.txt"
        [ -s "$p5dir/live-js-files.txt" ]       && cat "$p5dir/live-js-files.txt"
        [ -s "$p5dir/api-endpoints.txt" ]        && cat "$p5dir/api-endpoints.txt"
    } 2>/dev/null | sort -u | wc -l)
    # Coerce to a single integer token as belt-and-suspenders against any
    # whitespace/newline creeping into the arithmetic operands.
    _raw_host_count=${_raw_host_count//[!0-9]/}
    _raw_url_count=${_raw_url_count//[!0-9]/}
    : "${_raw_host_count:=0}" "${_raw_url_count:=0}"
    _dropped_hosts=$(( _raw_host_count - $(count_lines "$host_targets") ))
    _dropped_urls=$((  _raw_url_count  - $(count_lines "$combined_targets") ))

    info "Target lists — hosts: $(count_lines "$host_targets")  URLs: $(count_lines "$combined_targets")"
    if [ "$_dropped_hosts" -gt 0 ] || [ "$_dropped_urls" -gt 0 ]; then
        info "Scope filter dropped $_dropped_hosts out-of-scope host(s) and $_dropped_urls out-of-scope URL(s)."
    fi

    if [ ! -s "$host_targets" ]; then
        warn "All live hosts were filtered out as out-of-scope for TARGET=$TARGET. Skipping Phase 7."
        merge_phase_backup "$p7dir"
        save_checkpoint 7
        polite_sleep
        return 0
    fi

    # 7.1 Consolidated severity scan against host roots only
    # BUG-2 FIX: -stats gives per-template progress so long runs don't appear
    # hung.  -stats-interval 30 logs a status line every 30 s without drowning
    # output.
    # CONCURRENCY FIX: -c/-bs now honour NUCLEI_CONCURRENCY (set per scan mode)
    # instead of a hardcoded 40.  -mhe is set to match so the error-ceiling is
    # always ≥ the worker count, eliminating the "[WRN] concurrency > max-host-
    # error" warning and preventing mid-scan host skips on fragile targets.
    info "Running consolidated Nuclei scan ($NUCLEI_SEVERITY severity)..."
    authorized_run validation list "$host_targets" nuclei -l @AUTHORIZED_INPUT@ \
        -severity "$NUCLEI_SEVERITY" \
        -exclude-tags headers,cookie-flags,info \
        -rate-limit "$NUCLEI_RATE_LIMIT" \
        -c "$NUCLEI_CONCURRENCY" -bs "$NUCLEI_CONCURRENCY" \
        -mhe "$NUCLEI_CONCURRENCY" \
        -timeout 10 \
        -stats -stats-interval 30 \
        -stats-json "$p7dir/scan1-stats.json" \
        -je "$p7dir/all-findings.json" \
        -o "$p7dir/all-findings.txt" \
        2>"$p7dir/scan1-nuclei.log"
    local scan1_rc=$?
    if [ "$scan1_rc" -ne 0 ]; then
        warn "Nuclei severity scan exited with code $scan1_rc; partial output was preserved."
        phase_status=1
    fi
    _p7_report_skips "$p7dir/scan1-nuclei.log" "7.1 severity scan"

    # 7.2 Exposure / misconfig scan against the full URL list
    # BUG-4 FIX: Add -exclude-severity info so info-severity exposure templates
    # (e.g. cookie attribute checkers) are excluded even when the -tags filter
    # pulls them in.  Previously -exclude-tags info only excluded templates
    # carrying the "info" tag, which is a different dimension from severity;
    # many high-volume info-severity exposure templates carry no such tag and
    # slipped through, dramatically inflating this scan's template corpus and
    # wall-clock time.  Using -es info is the correct, severity-level gate.
    #
    # CONCURRENCY FIX: 7.2 targets the full URL corpus (potentially hundreds of
    # paths per host).  A host-error skip here is more damaging than in 7.1
    # because many templates are path-aware and won't retry.  We therefore cap
    # concurrency at half of NUCLEI_CONCURRENCY (floored at 10) so the error
    # budget is never exhausted by a burst of parallel workers against one host.
    local _p7_url_conc=$(( NUCLEI_CONCURRENCY / 2 ))
    [ "$_p7_url_conc" -lt 10 ] && _p7_url_conc=10
    info "Scanning for exposures and misconfigurations..."
    authorized_run validation list "$combined_targets" nuclei -l @AUTHORIZED_INPUT@ \
        -tags exposure,config,misconfig \
        -exclude-tags headers,cookie-flags \
        -exclude-severity info \
        -rate-limit "$NUCLEI_RATE_LIMIT" \
        -c "$_p7_url_conc" -bs "$_p7_url_conc" \
        -mhe "$_p7_url_conc" \
        -timeout 10 \
        -stats -stats-interval 30 \
        -stats-json "$p7dir/scan2-stats.json" \
        -je "$p7dir/exposure-findings.json" \
        -o "$p7dir/exposure-findings.txt" \
        2>"$p7dir/scan2-nuclei.log"
    local scan2_rc=$?
    if [ "$scan2_rc" -ne 0 ]; then
        warn "Nuclei exposure scan exited with code $scan2_rc; partial output was preserved."
        phase_status=1
    fi
    _p7_report_skips "$p7dir/scan2-nuclei.log" "7.2 exposure scan"

    # 7.3 Split consolidated JSON into the category files other phases expect
    # BUG-5 FIX: nuclei -je (--json-export) emits a JSON ARRAY, not JSONL.
    # The previous code used bare `jq -r 'select(...)'` which applies select()
    # to the array object itself, not its elements → silent empty output for
    # every category file even when all-findings.json has real findings.
    # Correct form: `.[] | select(...)` to iterate array elements first.
    #
    # BUG-6 FIX: The previous code ran six independent jq passes over the same
    # JSON file.  We now use a single jq pass that writes all six category files
    # at once via output redirection, eliminating five redundant file reads.
    info "Splitting findings into category files..."

    # Initialise all output files (guarantees they exist even with zero matches)
    for _cf in critical-findings high-medium-findings cve-findings \
                js-exposure-findings api-findings endpoint-findings; do
        : > "$p7dir/${_cf}.txt"
    done

    # Single-pass categorisation — one jq invocation, one file read.
    # Each element is routed to one or more categories; a finding may appear in
    # multiple files (e.g. a critical CVE against an admin endpoint lands in
    # critical-findings, cve-findings, AND endpoint-findings).
    local category_routes="$p7dir/.category-routes.tmp.$$"
    if jq -r '
      .[] |
      (. ["template-id"] + " " + .host) as $line |
      (.info.severity // "unknown") as $sev |
      (. ["template-id"] // "") as $tid |
      (.host // "") as $host |
      if $sev == "critical" then "critical\t\($line)" else empty end,
      if ($sev == "high" or $sev == "medium") then "high-medium\t\($line)" else empty end,
      if ($tid | test("^CVE-"; "i")) then "cve\t\($line)" else empty end,
      if ($host | test("\\.js(\\?|$)")) then "js-exposure\t\($line)" else empty end,
      if ($host | test("/api/|/v[0-9]+/|graphql|/rest/"; "i")) then "api\t\($line)" else empty end,
      if ($host | test("admin|login|dashboard|upload|config|backup|dev|staging|test|debug"; "i")) then "endpoint\t\($line)" else empty end
    ' "$p7dir/all-findings.json" > "$category_routes" 2>/dev/null; then
        while IFS=$'\t' read -r category line; do
            case "$category" in
                critical)    printf '%s\n' "$line" >> "$p7dir/critical-findings.txt" ;;
                high-medium) printf '%s\n' "$line" >> "$p7dir/high-medium-findings.txt" ;;
                cve)         printf '%s\n' "$line" >> "$p7dir/cve-findings.txt" ;;
                js-exposure) printf '%s\n' "$line" >> "$p7dir/js-exposure-findings.txt" ;;
                api)         printf '%s\n' "$line" >> "$p7dir/api-findings.txt" ;;
                endpoint)    printf '%s\n' "$line" >> "$p7dir/endpoint-findings.txt" ;;
            esac
        done < "$category_routes"
    elif [ -s "$p7dir/all-findings.json" ]; then
        warn "Failed to parse Nuclei JSON into category files."
        phase_status=1
    fi
    rm -f "$category_routes"

    [ -s "$p7dir/critical-findings.txt" ] && \
        success "🚨 CRITICAL findings! → $p7dir/critical-findings.txt"

    # Clean up temp files (happy path; SIGINT path is handled by _nullsec_cleanup)
    rm -f "$host_targets" "$combined_targets"

    # 7.4 Tally all findings
    # COUNT FIX: the previous form
    #     total_findings=$(jq 'length' all-findings.json 2>/dev/null || echo "0")
    # silently substituted "0" for any jq failure — missing file, malformed
    # JSON (e.g. nuclei killed mid-flush), empty file, jq absent, etc.  This
    # produced "Total findings: 0" runs even when scan1-nuclei.log clearly
    # showed dozens of matches.  We now:
    #   1. Check that the JSON file exists and is non-empty before invoking jq;
    #   2. Capture both jq's exit status and a separate text-file fallback;
    #   3. Warn loudly when the two counts disagree (a signal that the JSON
    #      export failed and findings exist only in the .txt output).
    local total_findings=0
    local text_findings
    text_findings=$(count_lines "$p7dir/all-findings.txt")

    if [ ! -s "$p7dir/all-findings.json" ]; then
        # JSON not produced — fall back to text count.  This commonly means
        # nuclei was killed by a signal before flushing JSON, or the template
        # set hit zero matches (in which case text_findings will also be 0).
        if [ "$text_findings" -gt 0 ]; then
            warn "all-findings.json missing or empty but all-findings.txt has $text_findings matches — JSON export failed."
            warn "Findings are preserved in $p7dir/all-findings.txt; downstream category split was skipped."
            total_findings="$text_findings"
        fi
    else
        local _jq_err
        _jq_err=$(mktemp)
        total_findings=$(jq 'length' "$p7dir/all-findings.json" 2>"$_jq_err")
        local _jq_exit=$?
        if [ "$_jq_exit" -ne 0 ] || ! [[ "$total_findings" =~ ^[0-9]+$ ]]; then
            warn "jq failed to parse all-findings.json (exit $_jq_exit). Falling back to text-line count."
            [ -s "$_jq_err" ] && warn "  jq stderr: $(head -1 "$_jq_err")"
            total_findings="$text_findings"
        elif [ "$total_findings" -eq 0 ] && [ "$text_findings" -gt 0 ]; then
            # JSON parsed as empty array but text file has lines — schema
            # mismatch (nuclei version change) or path mismatch.
            warn "JSON reports 0 findings but all-findings.txt has $text_findings — possible export/version mismatch."
            warn "  Trusting text count; manually inspect $p7dir/all-findings.json"
            total_findings="$text_findings"
        fi
        rm -f "$_jq_err"
    fi

    local exposure_count
    exposure_count=$(count_lines "$p7dir/exposure-findings.txt")

    merge_phase_backup "$p7dir"
    success "Phase 7 complete! Total findings: $total_findings (+ $exposure_count exposure/misconfig)"

    # Notify on anything worth acting on immediately
    local p7_critical p7_high_med p7_cves
    p7_critical=$(count_lines "$p7dir/critical-findings.txt")
    p7_high_med=$(count_lines "$p7dir/high-medium-findings.txt")
    p7_cves=$(count_lines "$p7dir/cve-findings.txt")

    if [ "$p7_critical" -gt 0 ]; then
        notify "🔥 CRITICAL Vulns — Phase 7" \
            "*${p7_critical}* critical Nuclei finding(s) on \`${TARGET}\`.\nCheck: \`${p7dir}/critical-findings.txt\`"
    fi
    if [ "$p7_high_med" -gt 0 ]; then
        notify "⚠️ High/Medium Vulns — Phase 7" \
            "*${p7_high_med}* high/medium finding(s). CVEs: *${p7_cves}*.\nCheck: \`${p7dir}/high-medium-findings.txt\`"
    fi

    if [ "$phase_status" -ne 0 ]; then
        warn "Phase 7 completed with errors; checkpoint was not advanced."
        polite_sleep
        return 1
    fi
    save_checkpoint 7
    polite_sleep
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 8: JavaScript Analysis & Secret Extraction
# ─────────────────────────────────────────────────────────────────────────────
phase8_javascript_analysis() {
    authorization_allowed enumeration || { info "phase8_javascript_analysis: skipped by authorization policy"; return 0; }
    phase_done 8 && { polite_sleep; return 0; }
    print_phase "📜 PHASE 8: JAVASCRIPT ANALYSIS & SECRET EXTRACTION"

    if [ "$RUN_JS_ANALYSIS" = false ]; then
        info "JavaScript analysis skipped (mode: $SCAN_MODE)."
        return 0
    fi

    local p5dir="$OUTPUT_DIR/phase5-urls"
    local p8dir="$OUTPUT_DIR/phase8-javascript"
    local phase_status=0

    if [ ! -s "$p5dir/live-js-files.txt" ]; then
        warn "No live JS files found. Skipping Phase 8."
        return 0
    fi

    backup_phase_outputs "$p8dir"
    rm -rf "$p8dir/js-files"
    mkdir -p "$p8dir/js-files"

    local scoped_js="$p8dir/.scoped-js-input.txt"
    in_scope < "$p5dir/live-js-files.txt" | sort -u | head -n "$MAX_JS_FILES" > "$scoped_js"
    if [ ! -s "$scoped_js" ]; then
        warn "No in-scope JavaScript URLs remained after scope filtering."
        merge_phase_backup "$p8dir"
        rm -f "$scoped_js"
        return 0
    fi

    info "Downloading up to $MAX_JS_FILES JavaScript files..."
    local js_count=0 js_attempts=0 js_failures=0 total_bytes=0
    while IFS= read -r js_url && [ "$js_count" -lt "$MAX_JS_FILES" ]; do
        local filename tmp_file file_bytes
        filename=$(printf '%s' "$js_url" | sha256sum | awk '{print $1}')
        tmp_file="$p8dir/js-files/.${filename}.tmp.$$"
        js_attempts=$(( js_attempts + 1 ))
        if authorized_run enumeration host "$js_url" curl -q --proto '=http,https' --max-redirs 0 -fsk --max-time 15 --max-filesize "$MAX_JS_FILE_BYTES" \
            -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
            @AUTHORIZED_INPUT@ -o "$tmp_file" 2>/dev/null && [ -s "$tmp_file" ]; then
            file_bytes=$(wc -c < "$tmp_file")
            if [ $(( total_bytes + file_bytes )) -gt "$MAX_JS_TOTAL_BYTES" ]; then
                warn "Aggregate JavaScript download limit reached (${MAX_JS_TOTAL_BYTES} bytes); stopping."
                rm -f "$tmp_file"
                break
            fi
            mv -f "$tmp_file" "$p8dir/js-files/$filename.js"
            total_bytes=$(( total_bytes + file_bytes ))
            js_count=$(( js_count + 1 ))
        else
            rm -f "$tmp_file"
            js_failures=$(( js_failures + 1 ))
        fi
    done < "$scoped_js"
    rm -f "$scoped_js"
    success "Downloaded $js_count JavaScript files (${total_bytes} bytes); failures: $js_failures/$js_attempts"

    if [ "$js_count" -eq 0 ]; then
        error "Every JavaScript download failed or exceeded the configured limits."
        merge_phase_backup "$p8dir"
        return 1
    fi

    cat "$p8dir/js-files/"*.js > "$p8dir/all-js-content.txt" 2>/dev/null

    : > "$p8dir/trufflehog-secrets.json"
    : > "$p8dir/trufflehog-summary.txt"
    if authorization_allowed verification && check_command "trufflehog"; then
        info "Running TruffleHog for verified secret detection..."
        if authorized_run verification local-verification "$p8dir/js-files/" trufflehog filesystem @AUTHORIZED_INPUT@ --only-verified --json \
            > "$p8dir/trufflehog-secrets.json" 2>/dev/null; then
            jq -r 'select(.SourceMetadata != null) |
                "[" + .DetectorName + "] " + (.SourceMetadata.Data.Filesystem.file // "unknown")' \
                "$p8dir/trufflehog-secrets.json" 2>/dev/null \
                | sort -u > "$p8dir/trufflehog-summary.txt" || true
        else
            warn "TruffleHog failed; raw partial output was preserved."
            phase_status=1
        fi
    fi

    info "Extracting secrets with targeted regex patterns..."
    grep -oE 'AKIA[0-9A-Z]{16}' "$p8dir/all-js-content.txt" | sort -u > "$p8dir/aws-access-keys.txt" 2>/dev/null || : > "$p8dir/aws-access-keys.txt"
    grep -oE 'AIza[0-9A-Za-z_-]{35}' "$p8dir/all-js-content.txt" | sort -u > "$p8dir/google-api-keys.txt" 2>/dev/null || : > "$p8dir/google-api-keys.txt"
    grep -oE '(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,}' "$p8dir/all-js-content.txt" | sort -u > "$p8dir/github-tokens.txt" 2>/dev/null || : > "$p8dir/github-tokens.txt"
    grep -oE 'xox[baprs]-[0-9a-zA-Z-]{10,}' "$p8dir/all-js-content.txt" | sort -u > "$p8dir/slack-tokens.txt" 2>/dev/null || : > "$p8dir/slack-tokens.txt"
    grep -oE '(sk_live_|pk_live_)[0-9a-zA-Z]{24,}' "$p8dir/all-js-content.txt" | sort -u > "$p8dir/stripe-keys.txt" 2>/dev/null || : > "$p8dir/stripe-keys.txt"
    grep -i 'BEGIN.*PRIVATE KEY' "$p8dir/all-js-content.txt" | sort -u > "$p8dir/private-keys.txt" 2>/dev/null || : > "$p8dir/private-keys.txt"

    info "Secret extraction results:"
    echo "  TruffleHog verified : $(count_lines "$p8dir/trufflehog-summary.txt")"
    echo "  AWS Access Keys     : $(count_lines "$p8dir/aws-access-keys.txt")"
    echo "  Google API Keys     : $(count_lines "$p8dir/google-api-keys.txt")"
    echo "  GitHub Tokens       : $(count_lines "$p8dir/github-tokens.txt")"
    echo "  Slack Tokens        : $(count_lines "$p8dir/slack-tokens.txt")"
    echo "  Stripe Keys         : $(count_lines "$p8dir/stripe-keys.txt")"
    echo "  Private Keys        : $(count_lines "$p8dir/private-keys.txt")"

    info "Discovering in-scope API endpoints embedded in JavaScript..."
    local js_endpoints_tmp api_paths_tmp p3dir_ref="$OUTPUT_DIR/phase3-probing"
    js_endpoints_tmp=$(mktemp)
    api_paths_tmp=$(mktemp)

    grep -Eo 'https?://[a-zA-Z0-9./\-_?=&%#@:]+' "$p8dir/all-js-content.txt" 2>/dev/null \
        | in_scope >> "$js_endpoints_tmp" || true
    grep -oE '/api/[a-zA-Z0-9/_-]*' "$p8dir/all-js-content.txt" 2>/dev/null \
        | sort -u > "$api_paths_tmp" || true
    if [ -s "$api_paths_tmp" ] && [ -s "$p3dir_ref/live-hosts.txt" ]; then
        while IFS= read -r base; do
            while IFS= read -r api_path; do
                printf '%s%s\n' "${base%/}" "$api_path"
            done < "$api_paths_tmp"
        done < <(in_scope < "$p3dir_ref/live-hosts.txt") >> "$js_endpoints_tmp"
    fi
    sort -u "$js_endpoints_tmp" | in_scope > "$p8dir/js-endpoints.txt"
    rm -f "$js_endpoints_tmp" "$api_paths_tmp"

    : > "$p8dir/live-js-endpoints.txt"
    if [ -s "$p8dir/js-endpoints.txt" ]; then
        if ! authorized_run enumeration list "$p8dir/js-endpoints.txt" httpx-toolkit -l @AUTHORIZED_INPUT@ -silent -random-agent \
            -o "$p8dir/live-js-endpoints.txt" 2>/dev/null; then
            warn "HTTP probing of JS-derived endpoints failed; partial output was preserved."
            phase_status=1
        fi
        success "Live endpoints from JS: $(count_lines "$p8dir/live-js-endpoints.txt")"
    fi

    merge_phase_backup "$p8dir"
    success "Phase 8 complete!"

    local p8_secrets p8_aws p8_privkeys p8_total
    p8_secrets=$(count_lines "$p8dir/trufflehog-summary.txt")
    p8_aws=$(count_lines "$p8dir/aws-access-keys.txt")
    p8_privkeys=$(count_lines "$p8dir/private-keys.txt")
    p8_total=$(( p8_secrets + p8_aws + p8_privkeys ))
    if [ "$p8_total" -gt 0 ]; then
        notify "🔑 JS Secrets Found — Phase 8" \
            "Secrets extracted from JavaScript files:\nTruffleHog verified: *${p8_secrets}*\nAWS keys: *${p8_aws}*\nPrivate keys: *${p8_privkeys}*\nDir: \`${p8dir}\`"
    fi

    return "$phase_status"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 9: Vulnerability Pattern Hunting
# ─────────────────────────────────────────────────────────────────────────────
phase9_pattern_hunting() {
    authorization_allowed enumeration || { info "phase9_pattern_hunting: skipped by authorization policy"; return 0; }
    phase_done 9 && { polite_sleep; return; }
    print_phase "🎯 PHASE 9: VULNERABILITY PATTERN HUNTING"

    if [ "$RUN_PATTERN_HUNTING" = false ]; then
        info "Vulnerability pattern hunting skipped (mode: $SCAN_MODE)."
        return 0
    fi

    local phase_status=0
    local p9dir_backup="$OUTPUT_DIR/phase9-patterns"
    backup_phase_outputs "$p9dir_backup"
    : > "$p9dir_backup/cors-findings.txt"
    : > "$p9dir_backup/host-injection-findings.txt"
    : > "$p9dir_backup/dalfox-xss-confirmed.txt"
    rm -rf "$p9dir_backup/sqlmap-results"
    mkdir -p "$p9dir_backup/sqlmap-results"

    local p5dir="$OUTPUT_DIR/phase5-urls"
    local p9dir="$OUTPUT_DIR/phase9-patterns"
    local p3dir="$OUTPUT_DIR/phase3-probing"
    # Injection candidate sourcing: prefer the FULL injectable corpus (all
    # distinct param=value pairs, not liveness-gated) so SQLi/XSS/SSRF/LFI/IDOR
    # grep fallbacks see every testable value.  Fall back to the clean corpus
    # only if the injectable set is empty (e.g. target had no parametered URLs).
    local url_source="$p5dir/all-urls-injectable.txt"
    [ -s "$url_source" ] || url_source="$p5dir/all-urls.txt"

    # 9.1 SSRF candidates — prefer gf output (higher signal) over grep
    info "Finding SSRF candidates..."
    if [ -s "$p5dir/gf-ssrf.txt" ]; then
        cp "$p5dir/gf-ssrf.txt" "$p9dir/ssrf-candidates.txt"
    else
        grep -iE '(url|uri|path|dest|redirect|proxy|continue|view|target|load|fetch|host|ping)=' \
            "$url_source" > "$p9dir/ssrf-candidates.txt" 2>/dev/null || touch "$p9dir/ssrf-candidates.txt"
    fi
    success "SSRF candidates: $(count_lines "$p9dir/ssrf-candidates.txt")"

    # 9.2 Open Redirect candidates
    info "Finding Open Redirect candidates..."
    if [ -s "$p5dir/gf-redirect.txt" ]; then
        cp "$p5dir/gf-redirect.txt" "$p9dir/redirect-candidates.txt"
    else
        grep -iE '(redirect|url|next|return|redir|goto|continue|dest|forward|location)=' \
            "$url_source" > "$p9dir/redirect-candidates.txt" 2>/dev/null || touch "$p9dir/redirect-candidates.txt"
    fi
    success "Open Redirect candidates: $(count_lines "$p9dir/redirect-candidates.txt")"

    # 9.3 XSS candidates + Dalfox automated testing
    info "Finding XSS candidates..."
    if [ -s "$p5dir/gf-xss.txt" ]; then
        cp "$p5dir/gf-xss.txt" "$p9dir/xss-candidates.txt"
    else
        grep -iE '(q|search|query|keyword|s|name|p|callback|input|text|term|v)=' \
            "$url_source" > "$p9dir/xss-candidates.txt" 2>/dev/null || touch "$p9dir/xss-candidates.txt"
    fi
    success "XSS candidates: $(count_lines "$p9dir/xss-candidates.txt")"

    if authorization_allowed validation && check_command "dalfox" && [ -s "$p9dir/xss-candidates.txt" ]; then
        # Dedup candidates by INJECTION-POINT signature (host+path+param-keys),
        # keeping one concrete value per signature, BEFORE applying the cap.
        # Without this, head -N wastes the budget on ?id=1, ?id=2, ?id=3 — the
        # same injection point tested repeatedly.  After dedup, each of the N
        # capped slots is a DISTINCT injection point, so the same timeout budget
        # covers far more real attack surface.  This is the main reason dalfox
        # previously timed out without finding anything.
        awk '{ s=$0; gsub(/=[^&]*/,"=",s); if(!(seen[s]++)) print }' \
            "$p9dir/xss-candidates.txt" > "$p9dir/xss-candidates-dedup.txt"
        local xss_total xss_uniq
        xss_total=$(count_lines "$p9dir/xss-candidates.txt")
        xss_uniq=$(count_lines "$p9dir/xss-candidates-dedup.txt")
        info "Running Dalfox XSS testing (cap: ${XSS_CANDIDATE_CAP} distinct injection points of ${xss_uniq} found; ${xss_total} raw candidates, delay: ${DALFOX_DELAY}ms, workers: ${DALFOX_WORKERS:-10}, timeout: ${DALFOX_TIMEOUT}s)..."

        # `timeout DALFOX_TIMEOUT` is the primary guard against infinite hangs.
        # XSS_CANDIDATE_CAP bounds the input set.  --worker limits in-flight
        # requests so a throttling WAF doesn't tarpit us into the wall-clock
        # timeout, and per-request --timeout 10 stops a single hung request from
        # eating the whole budget.  dalfox writes findings incrementally, so a
        # timeout still preserves partial confirmed output.
        head -"${XSS_CANDIDATE_CAP}" "$p9dir/xss-candidates-dedup.txt" \
            | authorized_run validation stream "" timeout --kill-after=30 "${DALFOX_TIMEOUT}" \
                dalfox pipe \
                --silence \
                --no-color \
                --skip-bav \
                --worker "${DALFOX_WORKERS:-10}" \
                --timeout 10 \
                --delay "${DALFOX_DELAY}" \
                --output "$p9dir/dalfox-xss-confirmed.txt" 2>/dev/null
        local dalfox_exit=$?
        if [ "$dalfox_exit" -eq 124 ] || [ "$dalfox_exit" -eq 137 ]; then
            warn "Dalfox hit the ${DALFOX_TIMEOUT}s wall-clock timeout — partial results saved to $p9dir/dalfox-xss-confirmed.txt"
            phase_status=1
        elif [ "$dalfox_exit" -ne 0 ]; then
            warn "Dalfox exited with code $dalfox_exit — partial results were preserved."
            phase_status=1
        fi
        if [ -s "$p9dir/dalfox-xss-confirmed.txt" ]; then
            success "🚨 Dalfox confirmed XSS! → $p9dir/dalfox-xss-confirmed.txt"
        else
            info "Dalfox: no confirmed XSS."
        fi
    else
        ! check_command "dalfox" && warn "dalfox not installed — install hahwul/dalfox for automated XSS confirmation."
    fi

    # 9.4 SQL Injection candidates + SQLMap
    info "Finding SQLi candidates..."
    if [ -s "$p5dir/gf-sqli.txt" ]; then
        cp "$p5dir/gf-sqli.txt" "$p9dir/sqli-candidates.txt"
    else
        grep -iE '(id|select|report|role|update|query|user|sort|where|order|group|cat)=' \
            "$url_source" > "$p9dir/sqli-candidates.txt" 2>/dev/null || touch "$p9dir/sqli-candidates.txt"
    fi
    success "SQLi candidates: $(count_lines "$p9dir/sqli-candidates.txt")"

    if authorization_allowed validation && check_command "sqlmap" && [ -s "$p9dir/sqli-candidates.txt" ]; then
        # Dedup by injection-point signature first (same rationale as dalfox):
        # without it, the cap is spent re-testing ?id=1/?id=2 instead of distinct
        # injectable endpoints.  sqlmap detects injection from the parameter, not
        # the specific value, so one representative per signature is sufficient
        # and dramatically widens coverage under the same cap/timeout.
        awk '{ s=$0; gsub(/=[^&]*/,"=",s); if(!(seen[s]++)) print }' \
            "$p9dir/sqli-candidates.txt" > "$p9dir/sqli-candidates-dedup.txt"
        local sqli_total sqli_uniq
        sqli_total=$(count_lines "$p9dir/sqli-candidates.txt")
        sqli_uniq=$(count_lines "$p9dir/sqli-candidates-dedup.txt")
        info "Running SQLMap on up to ${SQLI_CANDIDATE_CAP} of ${sqli_uniq} distinct injection points (${sqli_total} raw; timeout: ${SQLMAP_TIMEOUT}s)..."
        head -"${SQLI_CANDIDATE_CAP}" "$p9dir/sqli-candidates-dedup.txt" \
            > "$p9dir/sqli-top${SQLI_CANDIDATE_CAP}.txt"

        # Retain the existing SQLMap target regex as a tool-specific hint.
        # It is not a sandbox for redirects, exclusions, or internal requests.
        local escaped_target
        escaped_target=$(echo "$TARGET" | sed 's/\./\\./g')

        # level=2/risk=2 broadens coverage (more parameters incl. Cookie/headers
        # and more injection techniques) without entering destructive risk=3
        # territory — appropriate for a VDP.  --threads parallelises within a
        # target; per-request --timeout + capped --retries keep a throttling WAF
        # from stalling the whole batch into the wall-clock timeout.
        authorized_run validation list "$p9dir/sqli-top${SQLI_CANDIDATE_CAP}.txt" timeout --kill-after=30 "${SQLMAP_TIMEOUT}" \
            sqlmap -m @AUTHORIZED_INPUT@ \
                --batch \
                --smart \
                --level=2 \
                --risk=2 \
                --threads=4 \
                --delay=1 \
                --random-agent \
                --scope="^https?://([^/@]+@)?([a-zA-Z0-9-]+\\.)*${escaped_target}(:[0-9]+)?([/?#]|$)" \
                --tamper=between,randomcase \
                --timeout=15 \
                --retries=1 \
                --output-dir="$p9dir/sqlmap-results" \
                2>/dev/null
        local sqlmap_exit=$?
        if [ "$sqlmap_exit" -eq 124 ] || [ "$sqlmap_exit" -eq 137 ]; then
            warn "SQLMap hit the ${SQLMAP_TIMEOUT}s wall-clock timeout — partial results in $p9dir/sqlmap-results/"
            phase_status=1
        elif [ "$sqlmap_exit" -ne 0 ]; then
            warn "SQLMap exited with code $sqlmap_exit — partial results were preserved."
            phase_status=1
        else
            success "SQLMap scan complete → $p9dir/sqlmap-results/"
        fi
    fi

    # 9.5 LFI candidates
    info "Finding LFI candidates..."
    if [ -s "$p5dir/gf-lfi.txt" ]; then
        cp "$p5dir/gf-lfi.txt" "$p9dir/lfi-candidates.txt"
    else
        grep -iE '(file|path|folder|include|doc|page|archive|download|template|dir)=' \
            "$url_source" > "$p9dir/lfi-candidates.txt" 2>/dev/null || touch "$p9dir/lfi-candidates.txt"
    fi
    success "LFI candidates: $(count_lines "$p9dir/lfi-candidates.txt")"

    # 9.6 IDOR candidates — numeric IDs in parameters are prime IDOR targets
    info "Finding IDOR candidates (numeric param values)..."
    if [ -s "$p5dir/gf-idor.txt" ]; then
        cp "$p5dir/gf-idor.txt" "$p9dir/idor-candidates.txt"
    else
        grep -iE '(id|user_id|account|profile|order|invoice|ticket|record|member)=[0-9]+' \
            "$url_source" | sort -u > "$p9dir/idor-candidates.txt" 2>/dev/null \
            || touch "$p9dir/idor-candidates.txt"
    fi
    success "IDOR candidates: $(count_lines "$p9dir/idor-candidates.txt")"

    # 9.7 CORS misconfiguration testing (improved over v1)
    # v1 only checked for evil.nullsec.com in ACAO, missed the critical ACAC: true + ACAO: * case
    # Distinguishes CORS-CRITICAL (reflected origin) from CORS-HIGH (* + credentials)
    info "Testing CORS misconfigurations (up to $MAX_CORS_HOSTS hosts)..."
    local cors_count=0
    local cors_failures=0
    # BUG-7 FIX: Track a sliding window of the last N attempts so the throttle
    # bail-out reflects RECENT failure rate, not cumulative.  A target that
    # fails 5 requests then succeeds 50 should not trip this; the old check
    # divided lifetime-failures by lifetime-attempts, which permanently
    # poisoned the ratio on transient hiccups.  We use a fixed-size string
    # buffer of '1' (fail) / '0' (ok) characters and recompute the rate
    # against the window only.
    local cors_window=""
    local cors_window_size=20
    if authorization_allowed validation && [ -s "$p3dir/live-hosts.txt" ]; then
        while IFS= read -r url && [ $cors_count -lt $MAX_CORS_HOSTS ]; do
            local headers acao acac
            headers=$(authorized_run validation host "$url" curl -q --proto '=http,https' --max-redirs 0 -sk --max-time 5 \
                -H 'Origin: https://evil.nullsec.com' \
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
                -I @AUTHORIZED_INPUT@ 2>/dev/null)

            # Update sliding window — append result, trim to window_size
            local _result
            if [ -z "$headers" ]; then
                _result="1"
                cors_failures=$(( cors_failures + 1 ))
            else
                _result="0"
            fi
            cors_window="${cors_window}${_result}"
            if [ "${#cors_window}" -gt "$cors_window_size" ]; then
                cors_window="${cors_window:${#cors_window}-cors_window_size}"
            fi

            if [ -z "$headers" ]; then
                # Bail early only after a full window of measurements AND >25%
                # recent failure rate — avoids tripping on transient hiccups.
                if [ "${#cors_window}" -eq "$cors_window_size" ]; then
                    local _recent_fails
                    _recent_fails=$(echo -n "$cors_window" | tr -cd '1' | wc -c)
                    if [ $((_recent_fails * 100 / cors_window_size)) -gt 25 ]; then
                        warn "CORS scan: ${_recent_fails}/${cors_window_size} recent requests failed (>25%) — possible throttling. Stopping early."
                        break
                    fi
                fi
                cors_count=$(( cors_count + 1 ))
                continue
            fi

            acao=$(echo "$headers" | grep -i 'access-control-allow-origin' | tr -d '\r')
            acac=$(echo "$headers" | grep -i 'access-control-allow-credentials' | tr -d '\r')

            # BUG-6 FIX: $acao contains the full header line
            # "Access-Control-Allow-Origin: null", so a regex anchored with
            # ^null$ can never match.  Extract just the header VALUE (after
            # the colon, whitespace-trimmed) for the null-origin and
            # wildcard-with-credentials tests below.  The reflected-origin
            # case still works on the full line because "evil.nullsec.com"
            # appears as a substring either way.
            local acao_value acac_value
            acao_value=$(echo "$acao" | sed -E 's/^[^:]*:[[:space:]]*//; s/[[:space:]]+$//')
            acac_value=$(echo "$acac" | sed -E 's/^[^:]*:[[:space:]]*//; s/[[:space:]]+$//')

            local acao_lower acac_lower
            acao_lower=$(printf '%s' "$acao_value" | tr '[:upper:]' '[:lower:]')
            acac_lower=$(printf '%s' "$acac_value" | tr '[:upper:]' '[:lower:]')

            # Only report an origin that exactly reflects the Origin sent in this
            # request. ACAO:null was not tested with Origin:null, and ACAO:* with
            # credentials is rejected by browsers, so neither is exploitable here.
            if [ "$acao_lower" = "https://evil.nullsec.com" ]; then
                if [ "$acac_lower" = "true" ]; then
                    echo "[CORS-CRITICAL] $url | exact origin reflection + credentials | $acao | $acac" >> "$p9dir/cors-findings.txt"
                else
                    echo "[CORS-MEDIUM] $url | exact origin reflection without credentials | $acao" >> "$p9dir/cors-findings.txt"
                fi
            fi
            cors_count=$(( cors_count + 1 ))
        done < "$p3dir/live-hosts.txt"
    fi

    if [ -s "$p9dir/cors-findings.txt" ]; then
        success "🚨 CORS issues found: $(count_lines "$p9dir/cors-findings.txt")"
    else
        info "No CORS misconfigurations detected."
    fi
    [ "$cors_failures" -gt 0 ] && warn "CORS scan: $cors_failures/$cors_count requests failed (timeouts/resets)."

    # 9.8 Host Header Injection testing
    info "Testing for Host Header Injection..."
    local hhi_count=0
    local hhi_failures=0
    # BUG-7 FIX: Sliding-window throttle detection (see CORS loop above).
    local hhi_window=""
    local hhi_window_size=10
    if authorization_allowed validation && [ -s "$p3dir/live-hosts.txt" ]; then
        while IFS= read -r url && [ $hhi_count -lt 30 ]; do
            local resp
            resp=$(authorized_run validation host "$url" curl -q --proto '=http,https' --max-redirs 0 -sk --max-time 5 \
                -H 'Host: evil.nullsec.com' \
                -H 'X-Forwarded-Host: evil.nullsec.com' \
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
                @AUTHORIZED_INPUT@ 2>/dev/null)

            local _result
            if [ -z "$resp" ]; then
                _result="1"
                hhi_failures=$(( hhi_failures + 1 ))
            else
                _result="0"
            fi
            hhi_window="${hhi_window}${_result}"
            if [ "${#hhi_window}" -gt "$hhi_window_size" ]; then
                hhi_window="${hhi_window:${#hhi_window}-hhi_window_size}"
            fi

            if [ -z "$resp" ]; then
                if [ "${#hhi_window}" -eq "$hhi_window_size" ]; then
                    local _recent_fails
                    _recent_fails=$(echo -n "$hhi_window" | tr -cd '1' | wc -c)
                    if [ $((_recent_fails * 100 / hhi_window_size)) -gt 25 ]; then
                        warn "HHI scan: ${_recent_fails}/${hhi_window_size} recent requests failed (>25%) — possible throttling. Stopping early."
                        break
                    fi
                fi
                hhi_count=$(( hhi_count + 1 ))
                continue
            fi

            # BUG-9 FIX: grep -F treats the pattern as a literal string so the
            # dots in "evil.nullsec.com" are not interpreted as regex
            # any-character wildcards (previous: `grep -q 'evil.nullsec.com'`
            # would also match "evilXnullsecXcom" etc.).
            if echo "$resp" | grep -qF 'evil.nullsec.com'; then
                echo "[HOST-INJECTION] $url" >> "$p9dir/host-injection-findings.txt"
            fi
            hhi_count=$(( hhi_count + 1 ))
        done < "$p3dir/live-hosts.txt"
    fi

    if [ -s "$p9dir/host-injection-findings.txt" ]; then
        success "🚨 Host header injection candidates: $(count_lines "$p9dir/host-injection-findings.txt")"
    else
        info "No host header injection detected."
    fi
    [ "$hhi_failures" -gt 0 ] && warn "HHI scan: $hhi_failures/$hhi_count requests failed (timeouts/resets)."

    merge_phase_backup "$p9dir_backup"
    success "Phase 9 complete!"

    # Notify on high-signal pattern hits
    local p9_cors p9_ssrf p9_xss p9_hhi
    p9_cors=$(count_lines "$p9dir/cors-findings.txt")
    p9_ssrf=$(count_lines "$p9dir/ssrf-candidates.txt")
    p9_xss=$(count_lines "$p9dir/dalfox-xss-confirmed.txt")
    p9_hhi=$(count_lines "$p9dir/host-injection-findings.txt")
    local p9_total
    p9_total=$(( p9_cors + p9_ssrf + p9_xss + p9_hhi ))
    if [ "$p9_total" -gt 0 ]; then
        notify "🎯 Pattern Hits — Phase 9" \
            "Vulnerability patterns detected on \`${TARGET}\`:\nCORS misconfigs: *${p9_cors}*\nSSRF candidates: *${p9_ssrf}*\nXSS confirmed: *${p9_xss}*\nHost-header inject: *${p9_hhi}*"
    fi
    return "$phase_status"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 10: Screenshots & Visual Reconnaissance
# ─────────────────────────────────────────────────────────────────────────────
phase10_screenshots() {
    authorization_allowed enumeration || { info "phase10_screenshots: skipped by authorization policy"; return 0; }
    phase_done 10 && { polite_sleep; return 0; }
    print_phase "📸 PHASE 10: SCREENSHOTS & VISUAL RECONNAISSANCE"

    if [ "$RUN_SCREENSHOTS" = false ]; then
        info "Screenshots skipped (mode: $SCAN_MODE)."
        return 0
    fi

    local p3dir="$OUTPUT_DIR/phase3-probing"
    local p5dir="$OUTPUT_DIR/phase5-urls"
    local p10dir="$OUTPUT_DIR/phase10-screenshots"
    local phase_status=0

    if ! check_command "gowitness"; then
        warn "gowitness not installed — skipping Phase 10."
        return 0
    fi

    backup_phase_outputs "$p10dir"
    rm -rf "$p10dir/403" "$p10dir/interesting" "$p10dir/admin" "$p10dir/all"
    mkdir -p "$p10dir/403" "$p10dir/interesting" "$p10dir/admin" "$p10dir/all"

    _run_gowitness_batch() {
        local label="$1" input="$2" output_dir="$3" targets="$output_dir/targets.txt"
        [ -s "$input" ] || return 0
        head -"$MAX_SCREENSHOTS" "$input" | in_scope > "$targets"
        [ -s "$targets" ] || return 0
        info "Capturing $label screenshots (batch)..."
        if ! authorized_run enumeration list "$targets" gowitness scan file -f @AUTHORIZED_INPUT@ --screenshot-path "$output_dir/" \
            --threads "$GOWITNESS_THREADS" 2>/dev/null; then
            warn "Gowitness failed while capturing $label screenshots."
            return 1
        fi
        success "$label screenshots captured"
        return 0
    }

    _run_gowitness_batch "403 Forbidden" "$p3dir/status-403.txt" "$p10dir/403" || phase_status=1
    _run_gowitness_batch "sensitive endpoint" "$p5dir/sensitive-endpoints.txt" "$p10dir/interesting" || phase_status=1

    local admin_targets="$p10dir/admin/source-targets.txt"
    if [ -s "$p3dir/live-hosts.txt" ]; then
        grep -iE '(admin|manage|panel|dashboard|control)' "$p3dir/live-hosts.txt" \
            | in_scope > "$admin_targets" 2>/dev/null || : > "$admin_targets"
    fi
    _run_gowitness_batch "admin panel" "$admin_targets" "$p10dir/admin" || phase_status=1
    _run_gowitness_batch "live host" "$p3dir/live-hosts.txt" "$p10dir/all" || phase_status=1
    unset -f _run_gowitness_batch

    merge_phase_backup "$p10dir"
    success "Phase 10 complete!"
    return "$phase_status"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 11: Directory & Content Fuzzing  [NEW]
# ─────────────────────────────────────────────────────────────────────────────
phase11_fuzzing() {
    authorization_allowed validation || { info "phase11_fuzzing: skipped by authorization policy"; return 0; }
    phase_done 11 && { polite_sleep; return 0; }
    print_phase "💥 PHASE 11: DIRECTORY & CONTENT FUZZING"

    if [ "$RUN_FUZZING" = false ]; then
        info "Directory fuzzing skipped (mode: $SCAN_MODE)."
        return 0
    fi

    local p3dir="$OUTPUT_DIR/phase3-probing"
    local p11dir="$OUTPUT_DIR/phase11-fuzzing"
    local phase_status=0

    if ! check_command "ffuf"; then
        warn "ffuf not installed — skipping Phase 11."
        return 0
    fi
    if [ ! -s "$WEB_WORDLIST" ] || [ ! -r "$WEB_WORDLIST" ]; then
        warn "Web wordlist missing/empty/unreadable at $WEB_WORDLIST — skipping directory fuzzing."
        return 0
    fi
    if [ ! -s "$p3dir/status-200.txt" ]; then
        warn "No status-200 hosts available for fuzzing."
        return 0
    fi

    backup_phase_outputs "$p11dir"
    rm -rf "$p11dir/dirs"
    mkdir -p "$p11dir/dirs"

    local fuzz_input="$p11dir/.fuzz-targets-in-scope.txt"
    in_scope < "$p3dir/status-200.txt" | sort -u > "$fuzz_input"
    if [ ! -s "$fuzz_input" ]; then
        warn "No in-scope status-200 hosts for fuzzing (TARGET=$TARGET)."
        rm -f "$fuzz_input"
        merge_phase_backup "$p11dir"
        return 0
    fi

    local ffuf_log="$p11dir/.ffuf-errors.log"
    : > "$ffuf_log"
    : > "$p11dir/dirs/all-found-paths.txt"
    : > "$p11dir/dirs/all-found-backups.txt"

    info "Running recursive directory fuzzing on top 10 in-scope live hosts..."
    local fuzz_count=0
    while IFS= read -r url && [ "$fuzz_count" -lt 10 ]; do
        local safe_name output_json ffuf_rc
        safe_name=$(safe_artifact_name "$url")
        output_json="$p11dir/dirs/ffuf-$safe_name.json"
        info "  Fuzzing: $url"
        authorized_run validation host "${url%/}/FUZZ" timeout --signal=TERM --kill-after=10 "$FFUF_TIMEOUT" \
            ffuf -u @AUTHORIZED_INPUT@ -w "$WEB_WORDLIST" \
            -mc 200,201,204,301,302,307,401,403,405 \
            -t "$FFUF_THREADS" -rate 100 -o "$output_json" -of json \
            -recursion -recursion-depth 2 -ac -timeout 10 \
            >/dev/null 2>>"$ffuf_log"
        ffuf_rc=$?
        if [ "$ffuf_rc" -eq 124 ] || [ "$ffuf_rc" -eq 137 ]; then
            warn "ffuf timed out on $url after ${FFUF_TIMEOUT}s — partial results saved."
            phase_status=1
        elif [ "$ffuf_rc" -ne 0 ]; then
            warn "ffuf failed on $url with exit code $ffuf_rc."
            phase_status=1
        fi
        if [ -s "$output_json" ]; then
            jq -r '.results[]? | "\(.status) \(.url)"' "$output_json" 2>/dev/null \
                >> "$p11dir/dirs/all-found-paths.txt" || phase_status=1
        fi
        fuzz_count=$(( fuzz_count + 1 ))
    done < "$fuzz_input"
    sort -u -o "$p11dir/dirs/all-found-paths.txt" "$p11dir/dirs/all-found-paths.txt"
    success "Directory fuzzing complete: $(count_lines "$p11dir/dirs/all-found-paths.txt") paths found"

    local backup_wordlist="$SECLISTS/Discovery/Web-Content/raft-large-files.txt"
    if [ -s "$backup_wordlist" ] && [ -r "$backup_wordlist" ]; then
        info "Scanning for exposed backup and config files..."
        local backup_count=0
        while IFS= read -r url && [ "$backup_count" -lt 5 ]; do
            local safe_name output_json ffuf_rc
            safe_name=$(safe_artifact_name "$url")
            output_json="$p11dir/dirs/backups-$safe_name.json"
            authorized_run validation host "${url%/}/FUZZ" timeout --signal=TERM --kill-after=10 "$FFUF_TIMEOUT" \
                ffuf -u @AUTHORIZED_INPUT@ -w "$backup_wordlist" -mc 200 \
                -t "$FFUF_THREADS" -rate 100 -o "$output_json" -of json \
                -ac -timeout 10 >/dev/null 2>>"$ffuf_log"
            ffuf_rc=$?
            if [ "$ffuf_rc" -eq 124 ] || [ "$ffuf_rc" -eq 137 ]; then
                warn "Backup ffuf timed out on $url after ${FFUF_TIMEOUT}s."
                phase_status=1
            elif [ "$ffuf_rc" -ne 0 ]; then
                warn "Backup ffuf failed on $url with exit code $ffuf_rc."
                phase_status=1
            fi
            if [ -s "$output_json" ]; then
                jq -r '.results[]? | "\(.status) \(.url)"' "$output_json" 2>/dev/null \
                    >> "$p11dir/dirs/all-found-backups.txt" || phase_status=1
            fi
            backup_count=$(( backup_count + 1 ))
        done < "$fuzz_input"
        sort -u -o "$p11dir/dirs/all-found-backups.txt" "$p11dir/dirs/all-found-backups.txt"
        success "Backup file scan complete: $(count_lines "$p11dir/dirs/all-found-backups.txt") files found"
    fi

    if [ -s "$ffuf_log" ]; then
        local err_count
        err_count=$(wc -l < "$ffuf_log")
        warn "ffuf wrote $err_count stderr line(s). Tail (last 20):"
        tail -20 "$ffuf_log" | while IFS= read -r line; do warn "  → $line"; done
        info "Full ffuf stderr preserved at: $ffuf_log"
    fi

    rm -f "$fuzz_input"
    merge_phase_backup "$p11dir"
    success "Phase 11 complete!"
    return "$phase_status"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 12: Active Vulnerability Confirmation  [NEW]
# ─────────────────────────────────────────────────────────────────────────────
phase12_active_vulns() {
    authorization_allowed validation || { info "phase12_active_vulns: skipped by authorization policy"; return 0; }
    phase_done 12 && { polite_sleep; return 0; }
    print_phase "🔥 PHASE 12: ACTIVE VULNERABILITY CONFIRMATION"

    if [ "$RUN_ACTIVE_VULNS" = false ]; then
        info "Active vulnerability confirmation skipped (mode: $SCAN_MODE)."
        save_checkpoint 12
        return 0
    fi

    local p9dir="$OUTPUT_DIR/phase9-patterns"
    local p5dir="$OUTPUT_DIR/phase5-urls"
    local p12dir="$OUTPUT_DIR/phase12-active-vulns"
    local phase_status=0
    backup_phase_outputs "$p12dir"

    : > "$p12dir/ssrf-confirmed.txt"
    : > "$p12dir/redirect-confirmed.txt"
    : > "$p12dir/lfi-confirmed.txt"
    : > "$p12dir/403-bypass-confirmed.txt"
    : > "$p12dir/graphql-findings.txt"

    if [ -s "$p9dir/ssrf-candidates.txt" ]; then
        info "Testing SSRF candidates with Nuclei OAST templates..."
        if ! authorized_run validation list "$p9dir/ssrf-candidates.txt" nuclei -l @AUTHORIZED_INPUT@ -tags ssrf \
            -severity medium,high,critical -rate-limit "$NUCLEI_RATE_LIMIT" \
            -timeout 10 -o "$p12dir/ssrf-confirmed.txt" -silent 2>/dev/null; then
            warn "SSRF confirmation scan failed; partial output was preserved."
            phase_status=1
        fi
        [ -s "$p12dir/ssrf-confirmed.txt" ] && success "🚨 SSRF confirmed! → $p12dir/ssrf-confirmed.txt"
    fi

    if [ -s "$p9dir/redirect-candidates.txt" ]; then
        info "Confirming Open Redirect candidates with Nuclei..."
        if ! authorized_run validation list "$p9dir/redirect-candidates.txt" nuclei -l @AUTHORIZED_INPUT@ -tags redirect \
            -rate-limit "$NUCLEI_RATE_LIMIT" -timeout 10 \
            -o "$p12dir/redirect-confirmed.txt" -silent 2>/dev/null; then
            warn "Open-redirect confirmation scan failed; partial output was preserved."
            phase_status=1
        fi
        [ -s "$p12dir/redirect-confirmed.txt" ] && success "🚨 Open Redirects confirmed! → $p12dir/redirect-confirmed.txt"
    fi

    if [ -s "$p9dir/lfi-candidates.txt" ]; then
        info "Confirming LFI candidates with Nuclei..."
        if ! authorized_run validation list "$p9dir/lfi-candidates.txt" nuclei -l @AUTHORIZED_INPUT@ -tags lfi \
            -rate-limit "$NUCLEI_RATE_LIMIT" -timeout 10 \
            -o "$p12dir/lfi-confirmed.txt" -silent 2>/dev/null; then
            warn "LFI confirmation scan failed; partial output was preserved."
            phase_status=1
        fi
        [ -s "$p12dir/lfi-confirmed.txt" ] && success "🚨 LFI confirmed! → $p12dir/lfi-confirmed.txt"
    fi

    if [ -s "$OUTPUT_DIR/phase3-probing/status-403.txt" ]; then
        local bypass_template="$NUCLEI_TEMPLATES/http/fuzzing/403-bypass.yaml"
        if [ -f "$bypass_template" ]; then
            info "Attempting 403 Forbidden bypass techniques..."
            if ! authorized_run validation list "$OUTPUT_DIR/phase3-probing/status-403.txt" nuclei -l @AUTHORIZED_INPUT@ \
                -t "$bypass_template" \
                -rate-limit "$NUCLEI_RATE_LIMIT" -timeout 10 \
                -o "$p12dir/403-bypass-confirmed.txt" -silent 2>/dev/null; then
                warn "403-bypass confirmation scan failed; partial output was preserved."
                phase_status=1
            fi
            [ -s "$p12dir/403-bypass-confirmed.txt" ] && success "🚨 403 bypass found! → $p12dir/403-bypass-confirmed.txt"
        else
            warn "403-bypass template missing: $bypass_template — skipping 403 bypass confirmation."
        fi
    fi

    if [ -s "$p5dir/api-endpoints.txt" ]; then
        grep -i 'graphql' "$p5dir/api-endpoints.txt" | in_scope \
            | head -20 > "$p12dir/graphql-targets.txt" 2>/dev/null || : > "$p12dir/graphql-targets.txt"
        if [ -s "$p12dir/graphql-targets.txt" ]; then
            info "Testing GraphQL endpoints for introspection..."
            if ! authorized_run validation list "$p12dir/graphql-targets.txt" nuclei -l @AUTHORIZED_INPUT@ -tags graphql \
                -rate-limit "$NUCLEI_RATE_LIMIT" -timeout 10 \
                -o "$p12dir/graphql-findings.txt" -silent 2>/dev/null; then
                warn "GraphQL confirmation scan failed; partial output was preserved."
                phase_status=1
            fi
            [ -s "$p12dir/graphql-findings.txt" ] && success "🚨 GraphQL issues found! → $p12dir/graphql-findings.txt"
        fi
    fi

    merge_phase_backup "$p12dir"
    if [ "$phase_status" -ne 0 ]; then
        warn "Phase 12 completed with errors; checkpoint was not advanced."
        return 1
    fi
    success "Phase 12 complete!"
    save_checkpoint 12
    return 0
}

#==============================================================================#
#                           REPORT GENERATION                                  #
#==============================================================================#

generate_report() {
    local elapsed_mins="${1:-0}"
    local elapsed_secs="${2:-0}"

    print_phase "📋 GENERATING FINAL REPORT"

    local report_file="$OUTPUT_DIR/reports/recon-report.txt"
    backup_phase_outputs "$OUTPUT_DIR/reports"

    cat > "$report_file" << EOF
================================================================================
                    BUG BOUNTY RECONNAISSANCE REPORT
                         Generated by NULLSEC
================================================================================

TARGET         : $TARGET
DATE           : $(date)
OUTPUT DIR     : $OUTPUT_DIR
SCAN DURATION  : ${elapsed_mins}m ${elapsed_secs}s

================================================================================
                           EXECUTIVE SUMMARY
================================================================================

SUBDOMAIN DISCOVERY:
  Total Enumerated   : $(count_lines "$OUTPUT_DIR/phase1-subdomains/all-subdomains.txt")
  Resolved / Valid   : $(count_lines "$OUTPUT_DIR/phase2-validation/valid-subdomains.txt")
  Wildcards Filtered : $(count_lines "$OUTPUT_DIR/phase2-validation/wildcards.txt")

LIVE WEB SERVICES:
  Live Hosts         : $(count_lines "$OUTPUT_DIR/phase3-probing/live-hosts.txt")
  Status 200         : $(count_lines "$OUTPUT_DIR/phase3-probing/status-200.txt")
  Status 403         : $(count_lines "$OUTPUT_DIR/phase3-probing/status-403.txt")
  Status 401         : $(count_lines "$OUTPUT_DIR/phase3-probing/status-401.txt")
  Status 500         : $(count_lines "$OUTPUT_DIR/phase3-probing/status-500.txt")
  Hidden Vhost Candidates: $(count_lines "$OUTPUT_DIR/phase3-probing/discovered-vhosts.txt")

PORT SCANNING:
  Open Ports         : $(count_lines "$OUTPUT_DIR/phase4-portscan/open-ports.txt")
  Web on Alt Ports   : $(count_lines "$OUTPUT_DIR/phase4-portscan/services-on-ports.txt")

URL DISCOVERY:
  Raw Merged URLs    : $(count_lines "$OUTPUT_DIR/phase5-urls/all-urls-raw.txt")
  Refined URLs       : $(count_lines "$OUTPUT_DIR/phase5-urls/all-urls.txt")  [live, in-scope, param-collapsed]
  Injectable URLs    : $(count_lines "$OUTPUT_DIR/phase5-urls/all-urls-injectable.txt")  [full param values — feeds SQLi/XSS/IDOR]
  API Endpoints      : $(count_lines "$OUTPUT_DIR/phase5-urls/api-endpoints.txt")
  Sensitive Endpoints: $(count_lines "$OUTPUT_DIR/phase5-urls/sensitive-endpoints.txt")
  Live JS Files      : $(count_lines "$OUTPUT_DIR/phase5-urls/live-js-files.txt")

ASSET SCORING:
  Hosts Scored       : $(count_lines "$OUTPUT_DIR/asset-scoring/scored-targets.txt")
  Top Targets (25%)  : $(count_lines "$OUTPUT_DIR/asset-scoring/top-targets.txt")

NUCLEI FINDINGS:
  Critical           : $(count_lines "$OUTPUT_DIR/phase7-vulns/critical-findings.txt")
  High / Medium      : $(count_lines "$OUTPUT_DIR/phase7-vulns/high-medium-findings.txt")
  CVEs               : $(count_lines "$OUTPUT_DIR/phase7-vulns/cve-findings.txt")
  Exposures          : $(count_lines "$OUTPUT_DIR/phase7-vulns/exposure-findings.txt")
  Subdomain Takeover : $(count_lines "$OUTPUT_DIR/phase2-validation/takeover-findings.txt")

CLOUD STORAGE:
  S3 Buckets Found       : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/s3/exists.txt")
  S3 Readable            : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/s3/readable.txt")
  S3 WRITABLE (CRITICAL) : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/s3/writable.txt")
  GCS Buckets Found      : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/gcs/exists.txt")
  GCS Readable           : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/gcs/readable.txt")
  Unverified Names (NOTE): $(count_lines "$OUTPUT_DIR/phase2.5-cloud/exposed/unverified-candidates.txt")  [not probed without ownership evidence]
  Azure Accounts Found   : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/azure/exists.txt")
  Azure Readable         : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/azure/readable.txt")
  Total Exposed          : $(count_lines "$OUTPUT_DIR/phase2.5-cloud/exposed/all-exposed-buckets.txt")

JAVASCRIPT SECRETS:
  TruffleHog Verified: $(count_lines "$OUTPUT_DIR/phase8-javascript/trufflehog-summary.txt")
  AWS Access Keys    : $(count_lines "$OUTPUT_DIR/phase8-javascript/aws-access-keys.txt")
  Google API Keys    : $(count_lines "$OUTPUT_DIR/phase8-javascript/google-api-keys.txt")
  GitHub Tokens      : $(count_lines "$OUTPUT_DIR/phase8-javascript/github-tokens.txt")
  Slack Tokens       : $(count_lines "$OUTPUT_DIR/phase8-javascript/slack-tokens.txt")
  Stripe Keys        : $(count_lines "$OUTPUT_DIR/phase8-javascript/stripe-keys.txt")
  Private Keys       : $(count_lines "$OUTPUT_DIR/phase8-javascript/private-keys.txt")

PATTERN HUNTING:
  SSRF Candidates    : $(count_lines "$OUTPUT_DIR/phase9-patterns/ssrf-candidates.txt")
  Open Redirects     : $(count_lines "$OUTPUT_DIR/phase9-patterns/redirect-candidates.txt")
  XSS Candidates     : $(count_lines "$OUTPUT_DIR/phase9-patterns/xss-candidates.txt")
  XSS Confirmed      : $(count_lines "$OUTPUT_DIR/phase9-patterns/dalfox-xss-confirmed.txt")
  SQLi Candidates    : $(count_lines "$OUTPUT_DIR/phase9-patterns/sqli-candidates.txt")
  LFI Candidates     : $(count_lines "$OUTPUT_DIR/phase9-patterns/lfi-candidates.txt")
  IDOR Candidates    : $(count_lines "$OUTPUT_DIR/phase9-patterns/idor-candidates.txt")
  CORS Issues        : $(count_lines "$OUTPUT_DIR/phase9-patterns/cors-findings.txt")
  Host Header Inject : $(count_lines "$OUTPUT_DIR/phase9-patterns/host-injection-findings.txt")

DIRECTORY FUZZING:
  Paths Discovered   : $(count_lines "$OUTPUT_DIR/phase11-fuzzing/dirs/all-found-paths.txt")
  Backup/Config Files: $(count_lines "$OUTPUT_DIR/phase11-fuzzing/dirs/all-found-backups.txt")

ACTIVE CONFIRMATION:
  SSRF Confirmed     : $(count_lines "$OUTPUT_DIR/phase12-active-vulns/ssrf-confirmed.txt")
  Redirects Confirmed: $(count_lines "$OUTPUT_DIR/phase12-active-vulns/redirect-confirmed.txt")
  LFI Confirmed      : $(count_lines "$OUTPUT_DIR/phase12-active-vulns/lfi-confirmed.txt")
  403 Bypasses       : $(count_lines "$OUTPUT_DIR/phase12-active-vulns/403-bypass-confirmed.txt")
  GraphQL Issues     : $(count_lines "$OUTPUT_DIR/phase12-active-vulns/graphql-findings.txt")

================================================================================
                         CRITICAL / HIGH FINDINGS
================================================================================

EOF

    for findings_file in \
        "$OUTPUT_DIR/phase7-vulns/critical-findings.txt" \
        "$OUTPUT_DIR/phase7-vulns/high-medium-findings.txt" \
        "$OUTPUT_DIR/phase2-validation/takeover-findings.txt" \
        "$OUTPUT_DIR/phase2.5-cloud/exposed/critical-writable.txt" \
        "$OUTPUT_DIR/phase2.5-cloud/exposed/all-exposed-buckets.txt" \
        "$OUTPUT_DIR/phase9-patterns/dalfox-xss-confirmed.txt" \
        "$OUTPUT_DIR/phase9-patterns/cors-findings.txt" \
        "$OUTPUT_DIR/phase3-probing/vhost-findings.txt" \
        "$OUTPUT_DIR/phase11-fuzzing/dirs/all-found-backups.txt" \
        "$OUTPUT_DIR/phase12-active-vulns/ssrf-confirmed.txt" \
        "$OUTPUT_DIR/phase12-active-vulns/403-bypass-confirmed.txt" \
        "$OUTPUT_DIR/phase12-active-vulns/graphql-findings.txt"; do
        if [ -s "$findings_file" ]; then
            echo "--- $(basename "$findings_file") ---" >> "$report_file"
            cat "$findings_file" >> "$report_file"
            echo "" >> "$report_file"
        fi
    done

    # ── Top scored targets ───────────────────────────────────────────────────
    if [ -s "$OUTPUT_DIR/asset-scoring/scored-targets.txt" ]; then
        cat >> "$report_file" << EOF

================================================================================
                        TOP SCORED TARGETS (by attack potential)
================================================================================

EOF
        head -25 "$OUTPUT_DIR/asset-scoring/scored-targets.txt" >> "$report_file"
        echo "" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

================================================================================
                         SECRETS FOUND IN JAVASCRIPT
================================================================================

EOF

    for secret_file in \
        "$OUTPUT_DIR/phase8-javascript/trufflehog-summary.txt" \
        "$OUTPUT_DIR/phase8-javascript/aws-access-keys.txt" \
        "$OUTPUT_DIR/phase8-javascript/google-api-keys.txt" \
        "$OUTPUT_DIR/phase8-javascript/github-tokens.txt" \
        "$OUTPUT_DIR/phase8-javascript/slack-tokens.txt" \
        "$OUTPUT_DIR/phase8-javascript/stripe-keys.txt" \
        "$OUTPUT_DIR/phase8-javascript/private-keys.txt"; do
        if [ -s "$secret_file" ]; then
            echo "--- $(basename "$secret_file") ---" >> "$report_file"
            cat "$secret_file" >> "$report_file"
            echo "" >> "$report_file"
        fi
    done

    cat >> "$report_file" << EOF

================================================================================
                              END OF REPORT
================================================================================

Report generated by NullSec Framework v${VERSION}
Created by ${AUTHOR}
Happy Hunting! 🐛

================================================================================
EOF

    merge_phase_backup "$OUTPUT_DIR/reports"
    success "Report generated: $report_file"
}

#==============================================================================#
#                               MAIN EXECUTION                                 #
#==============================================================================#

main() {
    case "${1:-}" in
        --version)
            print_version
            exit 0
            ;;
        --help)
            usage 0
            ;;
    esac

    local RESUME_DIR="" OUTPUT_EXPLICIT=false MODE_CHANGED=false
    while getopts "d:o:m:surc:hI:E:C:AVK" opt; do
        case $opt in
            d) TARGET="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG"; OUTPUT_EXPLICIT=true ;;
            m) SCAN_MODE="$OPTARG" ;;
            s) SKIP_TOOL_CHECK=true ;;
            u) UPDATE_NUCLEI=true ;;
            r) RATE_LIMIT=true ;;
            c) RESUME_DIR="$OPTARG" ;;
            I) [ -n "$OPTARG" ] || { error "-I requires a nonempty policy path"; exit 1; }; INCLUDE_SCOPE_FILE="$OPTARG" ;;
            E) [ -n "$OPTARG" ] || { error "-E requires a nonempty policy path"; exit 1; }; EXCLUDE_SCOPE_FILE="$OPTARG" ;;
            C) [ -n "$OPTARG" ] || { error "-C requires a nonempty policy path"; exit 1; }; CLOUD_APPROVAL_FILE="$OPTARG" ;;
            A) ALLOW_ACTIVE_ENUM=true ;;
            V) ALLOW_ACTIVE_VALIDATION=true ;;
            K) ALLOW_SECRET_VERIFICATION=true ;;
            h) usage 0 ;;
            *) usage ;;
        esac
    done

    TARGET=$(printf '%s' "$TARGET" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')
    if [ -z "$TARGET" ]; then
        error "Target domain is required!"
        usage
    fi
    if ! [[ "$TARGET" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
        error "Target must be a plain DNS domain name with no URL, wildcard, path, IP, CIDR, or leading/trailing hyphen labels."
        exit 1
    fi
    if [ "$OUTPUT_EXPLICIT" = true ] && [ -n "$RESUME_DIR" ]; then
        error "Use either -o for a new scan or -c to resume, not both."
        exit 1
    fi

    if ! load_authorization_policy; then
        error "Invalid authorization policy; refusing all launches."
        exit 1
    fi
    if [ -n "$RESUME_DIR" ]; then
        if [ ! -d "$RESUME_DIR" ]; then
            error "Resume directory not found: $RESUME_DIR"
            exit 1
        fi
        OUTPUT_DIR="$(cd "$RESUME_DIR" && pwd)"
        local early_meta="$OUTPUT_DIR/.scan-meta"
        local early_checkpoint="$OUTPUT_DIR/.checkpoint"
        if [ ! -f "$early_meta" ]; then
            error "Resume refused: $early_meta is missing, so the directory cannot be safely bound to a target."
            exit 1
        fi
        if ! validate_resume_authorization "$early_meta"; then
            error "Resume refused: authorization fingerprint is missing, malformed, or differs from the current policy. Use a new output directory."
            exit 1
        fi
        local stored_target stored_mode
        stored_target=$(awk -F= '$1=="TARGET" {sub(/^[^=]*=/,""); print; exit}' "$early_meta")
        stored_mode=$(awk -F= '$1=="SCAN_MODE" {sub(/^[^=]*=/,""); print; exit}' "$early_meta")
        if [ "$stored_target" != "$TARGET" ]; then
            error "Resume target mismatch: directory belongs to '$stored_target', not '$TARGET'."
            exit 1
        fi
        if [ -n "$stored_mode" ] && [ "$stored_mode" != "$SCAN_MODE" ]; then
            warn "Scan mode changed from '$stored_mode' to '$SCAN_MODE'; restarting at Phase 1 inside the same target-bound directory."
            RESUME_FROM=0
            MODE_CHANGED=true
        elif [ -f "$early_checkpoint" ]; then
            RESUME_FROM=$(tr -cd '0-9.\n' < "$early_checkpoint" | head -1)
            [[ "${RESUME_FROM:-}" =~ ^[0-9]+([.][0-9]+)?$ ]] || RESUME_FROM=0
            info "Resuming scan from checkpoint $RESUME_FROM."
        else
            RESUME_FROM=0
            warn "No checkpoint file found — starting from Phase 1."
        fi
    else
        RESUME_FROM=0
        if [ -z "$OUTPUT_DIR" ]; then
            OUTPUT_DIR="./recon-$TARGET-$(date +%Y%m%d-%H%M%S)"
        elif [ -d "$OUTPUT_DIR" ] && [ -n "$(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
            error "Output directory is not empty: $OUTPUT_DIR"
            error "Choose a new -o directory or use -c to resume the existing scan."
            exit 1
        elif [ -e "$OUTPUT_DIR" ] && [ ! -d "$OUTPUT_DIR" ]; then
            error "Output path exists and is not a directory: $OUTPUT_DIR"
            exit 1
        fi
    fi

    local START_TIME
    START_TIME=$(date +%s)
    apply_scan_mode
    apply_authorization_controls
    print_banner

    info "Target          : $TARGET"
    info "Output Directory: $OUTPUT_DIR"
    info "Scan Mode       : $SCAN_MODE"
    info "Authorization   : enum=$ALLOW_ACTIVE_ENUM validation=$ALLOW_ACTIVE_VALIDATION secrets=$ALLOW_SECRET_VERIFICATION"
    info "Policy identity : $POLICY_FINGERPRINT"
    info "Nuclei Update   : $UPDATE_NUCLEI"
    info "Rate Limiting   : $RATE_LIMIT"
    info "Amass Timeout   : ${AMASS_TIMEOUT}s"
    resolve_nuclei_templates true || true
    echo ""

    [ "$SKIP_TOOL_CHECK" = false ] && check_tools

    info "Checking internet connectivity..."
    if ! authorized_run passive service https://1.1.1.1/cdn-cgi/trace curl -q --proto '=https' --max-redirs 0 -fsS --max-time 5 -o /dev/null @AUTHORIZED_INPUT@; then
        error "No internet connectivity detected. Check your network/VPN and try again."
        exit 1
    fi
    success "Internet connectivity OK"

    create_structure
    CHECKPOINT_FILE="$OUTPUT_DIR/.checkpoint"
    SCAN_META_FILE="$OUTPUT_DIR/.scan-meta"

    # A resumed run may revisit any earlier phase after a mode change or an
    # incomplete checkpoint. Snapshot every output type before direct redirects
    # or tool -o flags can replace prior evidence.
    if [ -n "$RESUME_DIR" ]; then
        snapshot_all_outputs
    fi

    local meta_tmp="${SCAN_META_FILE}.tmp.$$"
    if ! printf 'TARGET=%s\nSCAN_MODE=%s\nPOLICY_FINGERPRINT=%s\n' "$TARGET" "$SCAN_MODE" "$POLICY_FINGERPRINT" > "$meta_tmp" \
       || ! mv -f "$meta_tmp" "$SCAN_META_FILE"; then
        error "Could not bind output metadata to the authorization policy."
        exit 1
    fi
    if [ "$MODE_CHANGED" = true ]; then
        printf '0\n' > "$CHECKPOINT_FILE"
        RESUME_FROM=0
    fi

    local scan_failed=false
    _run_sequential_phase() {
        local label="$1" fn="$2"
        if ! "$fn"; then
            warn "$label returned an error; later phases may continue, but checkpoint advancement is frozen."
            scan_failed=true
            CHECKPOINT_FROZEN=true
            return 1
        fi
        return 0
    }

    _run_sequential_phase "Phase 1" phase1_subdomain_discovery || true
    _run_sequential_phase "Phase 2" phase2_validation || true
    _run_sequential_phase "Phase 2.5" phase2_5_cloud_enum || true
    _run_sequential_phase "Phase 3" phase3_probing || true
    _run_sequential_phase "Phase 4" phase4_portscan || true
    _run_sequential_phase "Phase 5" phase5_url_discovery || true
    _run_sequential_phase "Phase 6" phase6_parameters || true
    _run_sequential_phase "Asset scoring" phase_asset_scoring || true
    _run_sequential_phase "Phase 7" phase7_vulnerability_scanning || true
    unset -f _run_sequential_phase

    local -a parallel_pids=() parallel_names=() watchdog_pids=()
    _launch_parallel_phase() {
        local name="$1" fn="$2" wall_timeout="$3" pid watchdog gate parent_pid
        gate="$OUTPUT_DIR/.parallel-start.${BASHPID}.${#parallel_pids[@]}"
        parent_pid="$BASHPID"
        rm -f "$gate"

        # The child cannot launch scanners until the parent has recorded its PID.
        # If the parent dies before opening the gate, the blocked child exits on
        # its own without ever creating descendants.
        (
            trap - SIGINT SIGTERM
            while [ ! -e "$gate" ]; do
                kill -0 "$parent_pid" 2>/dev/null || exit 143
                sleep 0.05
            done
            rm -f "$gate"
            "$fn"
        ) &
        pid=$!
        parallel_pids+=("$pid")
        parallel_names+=("$name")
        _PARALLEL_PIDS+=("$pid")
        : > "$gate"

        (
            sleep "$wall_timeout"
            if kill -0 "$pid" 2>/dev/null; then
                warn "$name hit the ${wall_timeout}s wall-clock timeout — terminating its process tree."
                _terminate_process_tree "$pid" 10
            fi
        ) &
        watchdog=$!
        watchdog_pids+=("$watchdog")
        _PARALLEL_PIDS+=("$watchdog")
    }

    _launch_parallel_phase "Phase 8" phase8_javascript_analysis "$PHASE8_WALL_TIMEOUT"
    _launch_parallel_phase "Phase 9" phase9_pattern_hunting "$PHASE9_WALL_TIMEOUT"
    _launch_parallel_phase "Phase 10" phase10_screenshots "$PHASE10_WALL_TIMEOUT"
    _launch_parallel_phase "Phase 11" phase11_fuzzing "$PHASE11_WALL_TIMEOUT"
    unset -f _launch_parallel_phase

    local parallel_failed=false i exit_code
    for i in "${!parallel_pids[@]}"; do
        wait "${parallel_pids[$i]}" 2>/dev/null
        exit_code=$?
        if [ "$exit_code" -ne 0 ]; then
            if [ "$exit_code" -eq 143 ] || [ "$exit_code" -eq 137 ]; then
                warn "${parallel_names[$i]} was terminated by its wall-clock watchdog; partial results were preserved."
            else
                warn "${parallel_names[$i]} exited with code $exit_code."
            fi
            parallel_failed=true
        fi
    done

    local watchdog
    for watchdog in "${watchdog_pids[@]}"; do
        _terminate_process_tree "$watchdog" 1
    done
    _PARALLEL_PIDS=()
    rm -f "$OUTPUT_DIR"/.parallel-start.* 2>/dev/null || true

    if [ "$parallel_failed" = false ]; then
        success "Phases 8–11 completed in parallel."
        if [ "$CHECKPOINT_FROZEN" = false ]; then
            save_checkpoint 11
        fi
    else
        scan_failed=true
        CHECKPOINT_FROZEN=true
        warn "One or more parallel phases failed or timed out — checkpoint was not advanced to 11."
    fi

    if [ "$scan_failed" = false ]; then
        if ! phase12_active_vulns; then
            scan_failed=true
            CHECKPOINT_FROZEN=true
        fi
    else
        warn "Phase 12 skipped because prerequisite phases were incomplete."
    fi

    # Archive resume snapshots that were not already finalized by individual
    # phases. Successful zero-result reruns remain zero-result; prior evidence is
    # retained only under prior-runs rather than leaking into the current report.
    finalize_all_output_backups false

    local END_TIME ELAPSED_SECS elapsed_mins elapsed_secs
    END_TIME=$(date +%s)
    ELAPSED_SECS=$(( END_TIME - START_TIME ))
    elapsed_mins=$(( ELAPSED_SECS / 60 ))
    elapsed_secs=$(( ELAPSED_SECS % 60 ))
    generate_report "$elapsed_mins" "$elapsed_secs"

    local nc_subs nc_live nc_crit nc_high nc_buckets nc_secrets
    nc_subs=$(count_lines "$OUTPUT_DIR/phase1-subdomains/all-subdomains.txt")
    nc_live=$(count_lines "$OUTPUT_DIR/phase3-probing/live-hosts.txt")
    nc_crit=$(count_lines "$OUTPUT_DIR/phase7-vulns/critical-findings.txt")
    nc_high=$(count_lines "$OUTPUT_DIR/phase7-vulns/high-medium-findings.txt")
    nc_buckets=$(count_lines "$OUTPUT_DIR/phase2.5-cloud/exposed/all-exposed-buckets.txt")
    nc_secrets=$(count_lines "$OUTPUT_DIR/phase8-javascript/trufflehog-summary.txt")

    if [ "$scan_failed" = false ]; then
        notify "✅ Scan Complete — ${TARGET}" \
            "All enabled phases finished in *${elapsed_mins}m ${elapsed_secs}s*\n\nSubdomains: *${nc_subs}* | Live: *${nc_live}*\nCritical vulns: *${nc_crit}* | High/Med: *${nc_high}*\nExposed buckets: *${nc_buckets}* | JS secrets: *${nc_secrets}*\n\nReport: \`${OUTPUT_DIR}/reports/recon-report.txt\`"
        print_phase "🎉 RECONNAISSANCE COMPLETE!"
        success "All enabled phases completed successfully."
    else
        notify "⚠️ Partial Scan — ${TARGET}" \
            "The scan finished with incomplete phase(s) after *${elapsed_mins}m ${elapsed_secs}s*. Partial evidence was preserved.\nResume: \`$0 -d ${TARGET} -m ${SCAN_MODE} -c ${OUTPUT_DIR}\`"
        print_phase "⚠️  RECONNAISSANCE PARTIALLY COMPLETE"
        warn "One or more phases failed or timed out; do not treat this as a complete scan."
    fi

    info "Output Directory : $OUTPUT_DIR"
    info "Report           : $OUTPUT_DIR/reports/recon-report.txt"
    info "Total Scan Time  : ${elapsed_mins}m ${elapsed_secs}s"

    [ "$scan_failed" = false ]
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
