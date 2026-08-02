#!/bin/bash

set -uo pipefail
LC_ALL=C
export LC_ALL
umask 077

case ${BASH_SOURCE[0]} in */*) test_dir=${BASH_SOURCE[0]%/*} ;; *) test_dir=. ;; esac
builtin cd -P -- "$test_dir" || exit 1
test_dir=$PWD
repo=${test_dir%/tests}
launcher="$repo/nullsec-wolt-stage2a.sh"
core="$repo/lib/wolt-stage2a.py"
fixtures="$test_dir/fixtures/wolt-stage2a"
tmp=$(/usr/bin/mktemp -d "${repo%/*}/wolt-stage2a-integration.XXXXXXXX") || exit 1
[[ -n $tmp && $tmp == "${repo%/*}/wolt-stage2a-integration."???????? && -d $tmp ]] || exit 1
trap '/bin/chmod -R u+rwX "$tmp" 2>/dev/null; /bin/rm -rf -- "$tmp"' EXIT HUP INT TERM

pass=0 fail=0 skip=0
ok() { pass=$((pass + 1)); builtin printf 'ok - %s\n' "$1"; }
not_ok() { fail=$((fail + 1)); builtin printf 'not ok - %s\n' "$1" >&2; }
check_status() { local want=$1 label=$2; shift 2; "$@" >"$tmp/stdout" 2>"$tmp/stderr"; local got=$?; [[ $got -eq $want ]] && ok "$label" || not_ok "$label (got=$got want=$want)"; }

snapshot_repo() {
    local output=$1
    {
        builtin printf 'status\n'; git -C "$repo" status --short
        builtin printf 'tracked\n'
        git -C "$repo" ls-files -s
        git -C "$repo" ls-files -z | while IFS= read -r -d '' path; do
            /usr/bin/sha256sum "$repo/$path"
            /usr/bin/stat -c '%n|%a|%u|%g|%F' "$repo/$path"
        done
    } >"$output"
}

snapshot_repo "$tmp/repo-before"
/usr/bin/sha256sum "$repo/nullsec.sh" "$repo/nullsec-wolt.sh" \
    "$repo/config/wolt-approved-exact.txt" "$repo/config/wolt-excluded.txt" \
    "$repo/config/wolt-mobile-assets.txt" "$repo/config/wolt-policy.json" \
    "$repo/tests/test-wolt-wrapper.sh" >"$tmp/protected-before"
/usr/bin/stat -c '%n|%a|%u|%g' "$repo/nullsec.sh" "$repo/nullsec-wolt.sh" \
    "$repo/config/wolt-approved-exact.txt" "$repo/config/wolt-excluded.txt" \
    "$repo/config/wolt-mobile-assets.txt" "$repo/config/wolt-policy.json" \
    "$repo/tests/test-wolt-wrapper.sh" >"$tmp/protected-mode-before"

[[ $(/usr/bin/head -1 "$launcher") == '#!/bin/bash -p' ]] && ok 'exact privileged shebang' || not_ok 'exact privileged shebang'
[[ -x $launcher ]] && ok 'launcher executable mode' || not_ok 'launcher executable mode'
/bin/bash -n "$launcher" && /bin/bash -n "$test_dir/test-wolt-stage2a.sh" && ok 'shell syntax' || not_ok 'shell syntax'

production="$tmp/production"
/usr/bin/sed -n '1,$p' "$launcher" "$core" >"$production"
if ! /usr/bin/grep -E 'shell=True|(^|[^[:alnum:]_])eval\(|/usr/bin/id|/proc/' "$production" >/dev/null &&
   ! /usr/bin/grep -E '^[[:space:]]*(source|\.)[[:space:]]' "$launcher" >/dev/null; then
    ok 'no forbidden dynamic shell, id, or proc construct'
else not_ok 'no forbidden dynamic shell, id, or proc construct'; fi
if ! /usr/bin/grep -E '(^|["/ ])(curl|wget|dig|host|nslookup|getent|puredns|massdns|shuffledns|httpx|nuclei|naabu|nmap|ffuf|arjun|dalfox|sqlmap)([" /]|$)' "$production" >/dev/null; then
    ok 'no network executable path'
else not_ok 'no network executable path'; fi
if ! /usr/bin/grep -F 'nullsec.sh' "$production" >/dev/null; then ok 'no NullSec execution path'; else not_ok 'no NullSec execution path'; fi
if /usr/bin/grep -F 'exec /usr/bin/env -i LC_ALL=C /usr/bin/python3 -I -S' "$launcher" >/dev/null; then
    ok 'approved sanitized Python boundary'
else not_ok 'approved sanitized Python boundary'; fi

sentinels="$tmp/sentinels"; /bin/mkdir -m 700 "$sentinels"; sentinel_log="$tmp/sentinel.log"; : >"$sentinel_log"
names=(curl wget dig host nslookup getent puredns massdns shuffledns httpx nuclei naabu nmap ffuf arjun dalfox sqlmap subfinder assetfinder amass virustotal shodan nullsec.sh)
for name in "${names[@]}"; do
    builtin printf '#!/bin/bash\nbuiltin printf "%%s\\n" "%s" >>"%s"\nexit 125\n' "$name" "$sentinel_log" >"$sentinels/$name"
    /bin/chmod 700 "$sentinels/$name"
done
hostile="$tmp/hostile"; /bin/mkdir -m 700 "$hostile"; startup_log="$tmp/startup.log"
builtin printf 'builtin printf "BASH_ENV_RAN\\n" >>"%s"\n' "$startup_log" >"$tmp/bash-env"
stage2_canary_function() { builtin printf 'FUNCTION_RAN\n' >>"$startup_log"; }
export -f stage2_canary_function
alias stage2_canary_alias='false'
evidence="$tmp/evidence"; /bin/mkdir -m 700 "$evidence"
(
    builtin cd "$hostile" || exit 99
    PATH="$sentinels" BASH_ENV="$tmp/bash-env" ENV="$tmp/bash-env" HOME="$tmp/SECRET_HOME" \
    SUBFINDER_API_KEY=SECRET_SUBFINDER SHODAN_API_KEY=SECRET_SHODAN VT_API_KEY=SECRET_VT \
    "$launcher" --evidence-root "$evidence" \
      --import-source subfinder "$fixtures/inputs/subfinder-success.json" \
      --import-source assetfinder "$fixtures/inputs/assetfinder-success.json"
) >"$tmp/run-out" 2>"$tmp/run-err"
run_rc=$?
unset -f stage2_canary_function
[[ $run_rc -eq 0 && ! -e $startup_log ]] && ok 'hostile environment cannot alter direct launch' || not_ok 'hostile environment cannot alter direct launch'
[[ ! -s $sentinel_log ]] && ok 'network and provider sentinels untouched' || not_ok 'network and provider sentinels untouched'

run_id=$(/usr/bin/find "$evidence" -mindepth 1 -maxdepth 1 -type d ! -name 'INCOMPLETE-*' -printf '%f\n')
run="$evidence/$run_id"
check_status 0 'consumer accepts valid completed run' "$launcher" --validate-run "$run"
for file in approved-exact.txt wildcard-candidates-unreviewed.txt explicitly-excluded.txt rejected-non-wolt.txt rejected-mobile-assets.txt rejected-malformed.txt source-errors.txt provenance.tsv; do
    /usr/bin/cmp -s "$run/$file" "$fixtures/expected/$file" && ok "expected deterministic $file" || not_ok "expected deterministic $file"
done
[[ -f $run/COMPLETE && ! -s $run/COMPLETE ]] && ok 'zero-byte COMPLETE' || not_ok 'zero-byte COMPLETE'
[[ $(/usr/bin/find "$run" -mindepth 1 -maxdepth 1 | /usr/bin/wc -l) -eq 10 ]] && ok 'exact completed inventory' || not_ok 'exact completed inventory'
if ! /usr/bin/grep -R -E 'SECRET_(HOME|SUBFINDER|SHODAN|VT)' "$run" >/dev/null; then ok 'secret canaries absent'; else not_ok 'secret canaries absent'; fi

empty="$tmp/empty"; /bin/mkdir -m 700 "$empty"
check_status 0 'successful zero-record envelope' "$launcher" --evidence-root "$empty" --import-source amass "$fixtures/inputs/amass-empty.json"
failed="$tmp/failed"; /bin/mkdir -m 700 "$failed"
check_status 4 'failed envelope invalidates run' "$launcher" --evidence-root "$failed" --import-source shodan "$fixtures/inputs/shodan-failed.json"
if ! /usr/bin/find "$failed" -mindepth 1 -maxdepth 1 -type d ! -name 'INCOMPLETE-*' | /usr/bin/grep -q .; then ok 'failed run has no final directory'; else not_ok 'failed run has no final directory'; fi

incomplete="$evidence/INCOMPLETE-20990101T000000.000000000Z-0123456789abcdef"; /bin/mkdir -m 700 "$incomplete"; : >"$incomplete/COMPLETE"
check_status 6 'consumer rejects incomplete name with COMPLETE' "$launcher" --validate-run "$incomplete"

extra="$run/unexpected"; : >"$extra"
check_status 6 'consumer rejects unexpected file' "$launcher" --validate-run "$run"
/bin/rm "$extra"

/usr/bin/python3 -I -S "$test_dir/test-wolt-stage2a.py" >"$tmp/python-tests" 2>&1
python_rc=$?
[[ $python_rc -eq 0 ]] && ok 'Python unit and fault-injection suite' || { not_ok 'Python unit and fault-injection suite'; /bin/cat "$tmp/python-tests" >&2; }

snapshot_repo "$tmp/repo-after"
/usr/bin/sha256sum "$repo/nullsec.sh" "$repo/nullsec-wolt.sh" \
    "$repo/config/wolt-approved-exact.txt" "$repo/config/wolt-excluded.txt" \
    "$repo/config/wolt-mobile-assets.txt" "$repo/config/wolt-policy.json" \
    "$repo/tests/test-wolt-wrapper.sh" >"$tmp/protected-after"
/usr/bin/stat -c '%n|%a|%u|%g' "$repo/nullsec.sh" "$repo/nullsec-wolt.sh" \
    "$repo/config/wolt-approved-exact.txt" "$repo/config/wolt-excluded.txt" \
    "$repo/config/wolt-mobile-assets.txt" "$repo/config/wolt-policy.json" \
    "$repo/tests/test-wolt-wrapper.sh" >"$tmp/protected-mode-after"
/usr/bin/cmp -s "$tmp/protected-before" "$tmp/protected-after" && /usr/bin/cmp -s "$tmp/protected-mode-before" "$tmp/protected-mode-after" && ok 'protected files unchanged' || not_ok 'protected files unchanged'

/usr/bin/cmp -s "$tmp/repo-before" "$tmp/repo-after" && ok 'complete repository snapshot unchanged during tests' || not_ok 'complete repository snapshot unchanged during tests'

builtin printf 'SHELL_TEST_COUNTS pass=%d fail=%d skip=%d total=%d\n' "$pass" "$fail" "$skip" "$((pass + fail + skip))"
[[ $fail -eq 0 ]]
