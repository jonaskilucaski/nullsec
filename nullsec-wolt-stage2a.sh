#!/bin/bash -p

set -uo pipefail
LC_ALL=C
export LC_ALL
umask 077

startup_fail() {
    builtin printf '%s\n' STAGE2A_INTEGRITY_ERROR >&2
    exit 2
}

case $- in *p*) ;; *) startup_fail ;; esac
[[ ${UID:?} == "${EUID:?}" ]] || startup_fail
unset BASH_ENV ENV

[[ $0 == /* && ${BASH_SOURCE[0]} == /* ]] || startup_fail
[[ ! -L $0 && ! -L ${BASH_SOURCE[0]} ]] || startup_fail
case ${BASH_SOURCE[0]} in */*) launcher_dir=${BASH_SOURCE[0]%/*} ;; *) startup_fail ;; esac
builtin cd -P -- "$launcher_dir" || startup_fail
readonly REPOSITORY_DIR=$PWD
readonly LAUNCHER_PATH="$REPOSITORY_DIR/nullsec-wolt-stage2a.sh"
readonly PYTHON_CORE="$REPOSITORY_DIR/lib/wolt-stage2a.py"
[[ ${BASH_SOURCE[0]} == "$LAUNCHER_PATH" && ! -L $REPOSITORY_DIR ]] || startup_fail

exec /usr/bin/env -i LC_ALL=C /usr/bin/python3 -I -S \
    "$PYTHON_CORE" --repository "$REPOSITORY_DIR" \
    --launcher "$LAUNCHER_PATH" "$@"
