#!/bin/bash -p

set -euo pipefail
LC_ALL=C
export LC_ALL
umask 077

startup_fail() {
    builtin printf '%s\n' STAGE2C_INTEGRITY_ERROR >&2
    exit 2
}

case $- in *p*) ;; *) startup_fail ;; esac
[[ ${UID:?} == "${EUID:?}" ]] || startup_fail
unset BASH_ENV ENV CDPATH

# Supported entry: kernel shebang execution or equivalent explicit /bin/bash -p.
# Sourcing, PATH lookup, symlink launch, and ordinary unsupported Bash are rejected.
[[ $0 == */* && ${BASH_SOURCE[0]} == "$0" ]] || startup_fail
[[ ! -L $0 ]] || startup_fail
case $0 in */*) launcher_dir=${0%/*} ;; *) startup_fail ;; esac
builtin cd -P -- "$launcher_dir" 2>/dev/null || startup_fail
readonly REPOSITORY_DIR=$PWD
readonly LAUNCHER_PATH="$REPOSITORY_DIR/nullsec-wolt-stage2c.sh"
readonly PYTHON_CORE="$REPOSITORY_DIR/lib/wolt-stage2c.py"
readonly EXPECTED_CORE_SHA256=8a3054837da722dc96adee0bdf58817ed4075d1ddc2a8671e32d068815df835e
readonly EXPECTED_INTEGRITY_SCHEMA=1
readonly EXPECTED_INVENTORY_IDENTITY=b1578ab823271e0837f43fd607e6d98180b5221e92b47a676610ae734a036434
readonly EXPECTED_INVENTORY_AGGREGATE=5ed38e8f892e926ffba2a1f5d4651a57679eb9b30182a8dd9a525cf25f60cf88

[[ "$REPOSITORY_DIR/${0##*/}" == "$LAUNCHER_PATH" && ! -L $REPOSITORY_DIR &&
   -f $LAUNCHER_PATH && ! -L $LAUNCHER_PATH && -f $PYTHON_CORE && ! -L $PYTHON_CORE ]] || startup_fail

core_line=$(/usr/bin/sha256sum -- "$PYTHON_CORE" 2>/dev/null) || startup_fail
[[ ${core_line%% *} == "$EXPECTED_CORE_SHA256" ]] || startup_fail
unset core_line

# Non-recursive trust boundary: this chain does not protect against malicious
# same-UID replacement of both this launcher and the integrity manifest.
result_dir=
result_fd=
result_identity=
stdout_path=
stderr_path=
cleanup_private() {
    [[ -n ${result_dir:-} ]] || return 0
    if [[ -n ${result_fd:-} ]]; then
        if [[ -n $stdout_path && -n $stderr_path ]]; then
            /usr/bin/rm -f -- "$stdout_path" "$stderr_path" 2>/dev/null || return 1
        fi
        current_identity=$(/usr/bin/stat -c '%d:%i' -- "$result_dir" 2>/dev/null) || return 1
        [[ ! -L $result_dir && $current_identity == "$result_identity" ]] || return 1
        /usr/bin/rmdir -- "$result_dir" 2>/dev/null || return 1
        { exec {result_fd}<&-; } 2>/dev/null || return 1
        result_fd=
    else
        [[ $result_dir == /tmp/.nullsec-wolt-stage2c.???????? &&
           -d $result_dir && ! -L $result_dir ]] || return 1
        /usr/bin/rmdir -- "$result_dir" 2>/dev/null || return 1
    fi
    result_dir=
    return 0
}
trap 'cleanup_private >/dev/null 2>&1 || :' EXIT

result_dir=$(/usr/bin/mktemp -d -p /tmp .nullsec-wolt-stage2c.XXXXXXXX 2>/dev/null) || startup_fail
[[ $result_dir == /tmp/.nullsec-wolt-stage2c.???????? && -d $result_dir &&
   ! -L $result_dir ]] || startup_fail
result_meta=$(/usr/bin/stat -c '%f|%u|%a|%h' -- "$result_dir" 2>/dev/null) || startup_fail
[[ $result_meta == "41c0|$UID|700|2" ]] || startup_fail
unset result_meta

{ exec {result_fd}<"$result_dir"; } 2>/dev/null || startup_fail
result_identity=$(/usr/bin/stat -Lc '%d:%i' -- "/proc/$$/fd/$result_fd" 2>/dev/null) || startup_fail
stdout_path="/proc/$$/fd/$result_fd/stdout"
stderr_path="/proc/$$/fd/$result_fd/stderr"
{ : >"$stdout_path"; : >"$stderr_path"; } 2>/dev/null || startup_fail
result_meta=$(/usr/bin/stat -c '%f|%u|%a|%h' -- "$stdout_path" "$stderr_path" 2>/dev/null) || startup_fail
[[ $result_meta == $'8180|'"$UID"$'|600|1\n8180|'"$UID"'|600|1' ]] || startup_fail
unset result_meta

if (
    ulimit -S -f 4 || exit 125
    /usr/bin/python3 -I -S -B "$PYTHON_CORE" \
        --repository "$REPOSITORY_DIR" \
        --launcher "$LAUNCHER_PATH" \
        --integrity-schema "$EXPECTED_INTEGRITY_SCHEMA" \
        --inventory-identity "$EXPECTED_INVENTORY_IDENTITY" \
        --inventory-aggregate "$EXPECTED_INVENTORY_AGGREGATE" "$@" \
        >"$stdout_path" 2>"$stderr_path"
) 2>/dev/null; then
    child_status=0
else
    child_status=$?
fi

result_meta=$(/usr/bin/stat -c '%f|%u|%a|%h|%s' -- "$stdout_path" "$stderr_path" 2>/dev/null) || startup_fail
IFS='|' read -r stdout_mode_hex stdout_uid stdout_mode stdout_links stdout_size <<EOF
${result_meta%%$'\n'*}
EOF
IFS='|' read -r stderr_mode_hex stderr_uid stderr_mode stderr_links stderr_size <<EOF
${result_meta#*$'\n'}
EOF
[[ $stdout_mode_hex == 8180 && $stderr_mode_hex == 8180 &&
   $stdout_uid == "$UID" && $stderr_uid == "$UID" &&
   $stdout_mode == 600 && $stderr_mode == 600 &&
   $stdout_links == 1 && $stderr_links == 1 &&
   $stdout_size =~ ^[0-9]+$ && $stderr_size =~ ^[0-9]+$ &&
   $stdout_size -le 4096 && $stderr_size -le 4096 ]] || startup_fail
stdout_line=$(/usr/bin/sha256sum -- "$stdout_path" 2>/dev/null) || startup_fail
stderr_line=$(/usr/bin/sha256sum -- "$stderr_path" 2>/dev/null) || startup_fail
stdout_hash=${stdout_line%% *}
stderr_hash=${stderr_line%% *}
unset result_meta stdout_line stderr_line

empty_hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
case "$child_status:$stdout_size:$stdout_hash:$stderr_size:$stderr_hash" in
    0:30:fd0596f0857e0e0aa57db0a0a305796a74401dc9be868dec1bd760cba5fcd0d1:0:$empty_hash)
        public_code=0; public_result=success ;;
    0:369:f5714ca2e49443d4cd6a9b5936fb98fe5499e5ce9d0f6546e568b8f16f27709d:0:$empty_hash)
        public_code=0; public_result=help ;;
    1:0:$empty_hash:23:658d7cb911abbdb67d24451648ce177557343ac52962060ff27356f491f9eb18)
        public_code=1; public_result=STAGE2C_INTERNAL_ERROR ;;
    2:0:$empty_hash:24:eb44bab2f4d78a9c80a19bd2d9611aa011c49d32ffcbd663040c230ca6689f04)
        public_code=2; public_result=STAGE2C_INTEGRITY_ERROR ;;
    3:0:$empty_hash:20:baf04424dc987f96d2c479aa9d2d94c3e4be74497332e1f3a8d9fe31ebd12348)
        public_code=3; public_result=STAGE2C_INPUT_ERROR ;;
    4:0:$empty_hash:21:588667436a3ecf8494095d50dd156f5e9d0c2e064691daf43e74c934c5d7216b)
        public_code=4; public_result=STAGE2C_SCHEMA_ERROR ;;
    5:0:$empty_hash:20:73a05ff7fe73cee0bfd83d23789207e7089ab9b5f5cadd881b6bd0d9d29161d9)
        public_code=5; public_result=STAGE2C_CHILD_ERROR ;;
    6:0:$empty_hash:26:5f56cd9658a72d3be8e2a4db837654b7972d824c8392590613ea7ef57ff4ed88)
        public_code=6; public_result=STAGE2C_PUBLICATION_ERROR ;;
    7:0:$empty_hash:25:27e6ce470ce21e8c116d69de6237edbc809feed91e1f4e39ee00ee4fa2d962a4)
        public_code=7; public_result=STAGE2C_PROVIDER_FAILURE ;;
    8:0:$empty_hash:29:41aec0c620c2ccbcce52038a8155a13031f0607f9e147d57445a08f2ed90a8d2)
        public_code=8; public_result=STAGE2C_DURABILITY_UNCERTAIN ;;
    64:0:$empty_hash:20:9ea982c6567330f86e5a1be7e31c8596bfcf24d615fa629e31ff2563439e87d9)
        public_code=64; public_result=STAGE2C_USAGE_ERROR ;;
    *) startup_fail ;;
esac

cleanup_private || startup_fail
trap - EXIT
case $public_result in
    success) builtin printf '%s\n' STAGE2C_PHASE3_AGGREGATION_OK ;;
    help)
        builtin printf '%s\n' \
            'Usage: nullsec-wolt-stage2c.sh --help' \
            '       nullsec-wolt-stage2c.sh --manifest ABSOLUTE_FILE --output ABSOLUTE_NONEXISTENT_PATH' \
            'Phase 3 performs strictly offline retained-evidence normalization and deterministic in-memory aggregation.' \
            'It reuses only the fixed offline Stage 2B boundary; it does not classify, execute Stage 2A or NullSec, or perform final publication.' ;;
    *) builtin printf '%s\n' "$public_result" >&2 ;;
esac
exit "$public_code"
