# Read-only policy parsing. No target traffic belongs in this file.
# Normalize complete files before emitting anything: malformed/read-error input
# must never leave a partially usable policy on stdout.
normalize_authorization_file() {
    local kind="$1" path="$2" normalized
    [ -n "$path" ] || return 0
    if [ ! -f "$path" ] || [ ! -r "$path" ]; then
        printf 'Authorization file is not a readable regular file: %s\n' "$path" >&2
        return 1
    fi
    normalized=$(LC_ALL=C awk -v kind="$kind" '
        function trim(s) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", s); return s }
        function dns(s, parts,n,i) {
            if (length(s)>253 || s !~ /^[a-z0-9.-]+$/ || s !~ /\./ ||
                s ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 0
            n=split(s,parts,".")
            for(i=1;i<=n;i++) if(length(parts[i])<1 || length(parts[i])>63 ||
                parts[i] !~ /^[a-z0-9]/ || parts[i] !~ /[a-z0-9]$/) return 0
            return 1
        }
        function cloud(p,s, parts,n,i) {
            if(p=="azure") return length(s)>=3 && length(s)<=24 && s ~ /^[a-z0-9]+$/
            if(length(s)<3 || s !~ /^[a-z0-9]/ || s !~ /[a-z0-9]$/ ||
                s ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 0
            if(p=="s3") return length(s)<=63 && s ~ /^[a-z0-9.-]+$/ &&
                s !~ /\.\./ && s !~ /^(xn--|sthree-|amzn-s3-demo-)/ &&
                s !~ /(-s3alias|--ol-s3|\.mrap|--x-s3|--table-s3)$/
            if(p!="gcs" || length(s)>222 || s !~ /^[a-z0-9._-]+$/ ||
                s ~ /^goog/ || s ~ /(google|g00gle)/) return 0
            n=split(s,parts,".")
            if(n==1 && length(s)>63) return 0
            for(i=1;i<=n;i++) if(length(parts[i])<1 || length(parts[i])>63) return 0
            return 1
        }
        {
            sub(/#.*/, ""); line=trim($0)
            if(line=="") next
            if(kind=="cloud") {
                n=split(line,fields,":")
                p=tolower(trim(fields[1])); name=trim(fields[2])
                valid=(n==2 && name!="" && cloud(p,name))
                result=p ":" name
            } else {
                result=tolower(line); sub(/\.$/,"",result)
                host=result; sub(/^\*\./,"",host)
                valid=dns(host)
            }
            if(!valid) {
                printf "Malformed %s authorization rule at line %d\n",kind,NR > "/dev/stderr"
                bad=1
            } else rules[result]=1
        }
        END { if(bad) exit 1; for(rule in rules) print rule }
    ' < "$path") || return 1
    [ -z "$normalized" ] || printf '%s\n' "$normalized" | LC_ALL=C sort -u
}

authorization_manifest() {
    local includes excludes clouds flag
    for flag in "$ALLOW_ACTIVE_ENUMERATION" "$ALLOW_ACTIVE_VALIDATION" "$ALLOW_SECRET_VERIFICATION"; do
        case "$flag" in true|false) ;; *) printf 'Authorization flags must be true or false\n' >&2; return 1 ;; esac
    done
    includes=$(normalize_authorization_file host "${SCOPE_INCLUDE_FILE:-}") || return 1
    excludes=$(normalize_authorization_file host "${SCOPE_EXCLUDE_FILE:-}") || return 1
    clouds=$(normalize_authorization_file cloud "${CLOUD_APPROVAL_FILE:-}") || return 1
    printf 'schema=2\ntarget=%s\nenumeration=%s\nvalidation=%s\nverification=%s\n' \
        "$TARGET" "$ALLOW_ACTIVE_ENUMERATION" "$ALLOW_ACTIVE_VALIDATION" "$ALLOW_SECRET_VERIFICATION"
    if [ -n "${SCOPE_INCLUDE_FILE:-}" ]; then
        printf 'include-mode=explicit\n'
    else
        printf 'include-mode=target-descendants\n'
    fi
    [ -z "$includes" ] || printf '%s\n' "$includes" | sed 's/^/include=/'
    [ -z "$excludes" ] || printf '%s\n' "$excludes" | sed 's/^/exclude=/'
    [ -z "$clouds" ] || printf '%s\n' "$clouds" | sed 's/^/cloud=/'
    return 0
}

authorization_fingerprint() {
    local manifest digest
    manifest=$(authorization_manifest) || return 1
    digest=$(printf '%s\n' "$manifest" | sha256sum) || return 1
    printf '%s\n' "${digest%% *}"
}

assert_authorization_policy() {
    local current
    current=$(authorization_fingerprint) || return 1
    if [ -n "${AUTHORIZATION_FINGERPRINT:-}" ] && [ "$current" != "$AUTHORIZATION_FINGERPRINT" ]; then
        printf 'Authorization policy changed during execution; refusing further work.\n' >&2
        return 1
    fi
}

check_resume_authorization() {
    local metadata="$1" stored
    stored=$(awk -F= '$1=="AUTHORIZATION_SHA256" {print $2; n++} END {if(n!=1) exit 1}' "$metadata") || {
        printf 'Resume refused: authorization fingerprint is missing/ambiguous; start a new scan.\n' >&2
        return 1
    }
    if [ "$stored" != "$AUTHORIZATION_FINGERPRINT" ]; then
        printf 'Resume refused: authorization policy differs; use a new output directory.\n' >&2
        return 1
    fi
}

in_scope() {
    local manifest digest
    [ -n "${TARGET:-}" ] || return 1
    manifest=$(authorization_manifest) || return 1
    digest=$(printf '%s\n' "$manifest" | sha256sum) || return 1
    if [ -n "${AUTHORIZATION_FINGERPRINT:-}" ] && [ "${digest%% *}" != "$AUTHORIZATION_FINGERPRINT" ]; then
        printf 'Scope policy changed; refusing input.\n' >&2
        return 1
    fi
    LC_ALL=C awk -v policy="$manifest" -v target="$TARGET" '
        function matchrule(h,r,s) {
            if(substr(r,1,2)!="*.") return h==r
            s=substr(r,2)
            return length(h)>length(s) && substr(h,length(h)-length(s)+1)==s
        }
        function validhost(h,parts,n,i) {
            if(length(h)>253 || h !~ /^[a-z0-9.-]+$/ || h !~ /\./ ||
                h ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return 0
            n=split(h,parts,".")
            for(i=1;i<=n;i++) if(length(parts[i])<1 || length(parts[i])>63 ||
                parts[i] !~ /^[a-z0-9]/ || parts[i] !~ /[a-z0-9]$/) return 0
            return 1
        }
        BEGIN {
            n=split(policy,lines,"\n")
            for(i=1;i<=n;i++) {
                r=lines[i]
                if(r=="include-mode=explicit") explicit=1
                if(sub(/^include=/,"",r)) inc[++ni]=r
                r=lines[i]; if(sub(/^exclude=/,"",r)) exc[++ne]=r
            }
        }
        {
            line=$0; gsub(/^[[:space:]]+|[[:space:]]+$/,"",line)
            if(line=="" || line ~ /[[:space:]]/) next
            url=(tolower(line) ~ /^https?:\/\//)
            port=""
            h=line
            if(url) {sub(/^[^:]+:\/\//,"",h); sub(/[\/?#].*$/,"",h)}
            if(h ~ /@/ || h ~ /[\[\]]/) next
            if(h ~ /:/) {
                if(h !~ /:[0-9]+$/) next
                port=h; sub(/^.*:/,"",port)
                if(port+0<1 || port+0>65535) next
                sub(/:[0-9]+$/,"",h)
            }
            h=tolower(h); sub(/\.$/,"",h)
            if(!validhost(h)) next
            allowed=0
            if(explicit) {for(i=1;i<=ni;i++) if(matchrule(h,inc[i])) allowed=1}
            else allowed=(h==target || matchrule(h,"*." target))
            for(i=1;i<=ne;i++) if(matchrule(h,exc[i])) allowed=0
            if(allowed) print url ? line : h (port!="" ? ":" port : "")
        }
    '
}

require_authorized_request() {
    local accepted
    accepted=$(printf '%s\n' "$1" | in_scope) || return 1
    [ -n "$accepted" ] || { printf 'Request blocked by host authorization.\n' >&2; return 1; }
}

require_current_url_validation() {
    local state="$OUTPUT_DIR/phase5-urls/validation-state.txt" expected
    expected=$(authorization_fingerprint) || return 1
    if [ ! -f "$state" ] || ! awk -F= -v expected="$expected" '
        $1=="status" { statuses++; complete=($2=="complete") }
        $1=="authorization" { hashes++; matching=($2==expected) }
        END { exit !(statuses==1 && hashes==1 && complete && matching) }
    ' "$state"; then
        printf 'Current URL validation is incomplete or belongs to another policy.\n' >&2
        return 1
    fi
}

# Kept first so ~/.curlrc cannot inject URLs, proxies, credentials or redirects.
# Final options also override any inherited invocation-level -L.
curl() {
    assert_authorization_policy || return 1
    command curl --disable "$@" --no-location --proto '=http,https' --proto-redir '=http,https'
}

# Read help completely before matching it. Failed/unrecognized help is not
# evidence that the legacy wildcard contract is safe to use.
dnsx_wildcard_mode() {
    local help rc
    help=$(dnsx -h 2>&1); rc=$?
    [ "$rc" -eq 0 ] || { printf 'dnsx help failed (status %s)\n' "$rc" >&2; return 1; }
    if ! [[ "$help" =~ (^|[[:space:],])-l([[:space:],]|$) &&
            "$help" =~ (^|[[:space:],])-o([[:space:],]|$) &&
            "$help" =~ (^|[[:space:],])-silent([[:space:],]|$) ]]; then
        printf 'Incomplete dnsx help contract\n' >&2
        return 1
    fi
    if [[ "$help" =~ (^|[[:space:],])-auto-wildcard([[:space:],]|$) ]]; then
        printf 'auto\n'
    elif [[ "$help" =~ (^|[[:space:],])-wd([[:space:],]|$) &&
            "$help" =~ (^|[[:space:],])-wildcard-domain([[:space:],]|$) ]]; then
        printf 'manual\n'
    else
        printf 'Unrecognized dnsx wildcard CLI contract\n' >&2
        return 1
    fi
}

# Scope is re-applied at tool launch, including resumed/cached list inputs.
# This guards seeds; tool-internal template/browser egress needs its own adapter.
run_scoped_tool() {
    local category="$1" tool="$2"; shift 2
    local flag file scoped tmp="" url="" same_host=false rc
    local -a args=()
    assert_authorization_policy || return 1
    case "$category" in
        enumeration) [ "$ALLOW_ACTIVE_ENUMERATION" = true ] || return 1 ;;
        validation) [ "$ALLOW_ACTIVE_VALIDATION" = true ] || return 1 ;;
        baseline) ;;
        *) return 1 ;;
    esac
    while [ "$#" -gt 0 ]; do
        flag="$1"; shift
        case "$flag" in
            -l|-list|-m)
                [ "$#" -gt 0 ] || { [ -z "$tmp" ] || rm -f "$tmp"; return 1; }
                file="$1"; shift
                scoped=$(in_scope < "$file") || { [ -z "$tmp" ] || rm -f "$tmp"; return 1; }
                if [ -z "$scoped" ]; then
                    [ -z "$tmp" ] || rm -f "$tmp"
                    return 0
                fi
                [ -z "$tmp" ] || { rm -f "$tmp"; return 1; }
                tmp=$(mktemp "${OUTPUT_DIR:-${TMPDIR:-/tmp}}/.authorized-input.XXXXXX") || return 1
                printf '%s\n' "$scoped" > "$tmp" || { rm -f "$tmp"; return 1; }
                args+=("$flag" "$tmp")
                ;;
            -u)
                [ "$#" -gt 0 ] || { [ -z "$tmp" ] || rm -f "$tmp"; return 1; }
                url="$1"; shift
                require_authorized_request "$url" || { [ -z "$tmp" ] || rm -f "$tmp"; return 1; }
                args+=("$flag" "$url")
                ;;
            -follow-host-redirects|-fhr) same_host=true; args+=("$flag") ;;
            *) args+=("$flag") ;;
        esac
    done
    case "$tool" in
        httpx-toolkit) args+=(-fr=false "-fhr=$same_host") ;;
        ffuf) args+=(-r=false -recursion=false) ;;
        arjun) args+=(--disable-redirects) ;;
        sqlmap) args+=(--ignore-redirects) ;;
    esac
    case "$tool" in
        ffuf) command timeout --signal=TERM --kill-after=10 "$FFUF_TIMEOUT" "$tool" "${args[@]}" ;;
        sqlmap) command timeout --kill-after=30 "$SQLMAP_TIMEOUT" "$tool" "${args[@]}" ;;
        *) command "$tool" "${args[@]}" ;;
    esac
    rc=$?
    [ -z "$tmp" ] || rm -f "$tmp"
    return "$rc"
}

httpx-toolkit() { run_scoped_tool baseline httpx-toolkit "$@"; }
naabu() { run_scoped_tool enumeration naabu "$@"; }
arjun() { run_scoped_tool enumeration arjun "$@"; }
ffuf() { run_scoped_tool enumeration ffuf "$@"; }
sqlmap() { run_scoped_tool validation sqlmap "$@"; }
nuclei() { run_scoped_tool validation nuclei "$@"; }
dalfox() {
    local scoped
    [ "$ALLOW_ACTIVE_VALIDATION" = true ] || return 1
    scoped=$(in_scope) || return 1
    [ -n "$scoped" ] || return 0
    printf '%s\n' "$scoped" | command timeout --kill-after=30 "$DALFOX_TIMEOUT" dalfox "$@"
}
