#!/bin/bash -p

set -euo pipefail
LC_ALL=C
export LC_ALL
umask 077

startup_fail() {
    builtin printf '%s\n' STAGE2B_INTEGRITY_ERROR >&2
    exit 2
}

case $- in *p*) ;; *) startup_fail ;; esac
[[ ${UID:?} == "${EUID:?}" ]] || startup_fail
unset BASH_ENV ENV CDPATH

# Supported public entry: executable shebang launch or equivalent /bin/bash -p.
[[ $0 == */* && ${BASH_SOURCE[0]} == "$0" ]] || startup_fail
[[ ! -L $0 ]] || startup_fail
case $0 in */*) launcher_dir=${0%/*} ;; *) startup_fail ;; esac
builtin cd -P -- "$launcher_dir" || startup_fail
readonly REPOSITORY_DIR=$PWD
readonly LAUNCHER_PATH="$REPOSITORY_DIR/nullsec-wolt-stage2b.sh"
readonly PYTHON_CORE="$REPOSITORY_DIR/lib/wolt-stage2b.py"
[[ "$REPOSITORY_DIR/${0##*/}" == "$LAUNCHER_PATH" && ! -L $REPOSITORY_DIR && -f $PYTHON_CORE && ! -L $PYTHON_CORE ]] || startup_fail

exec /usr/bin/env -i LC_ALL=C /usr/bin/python3 -I -S -B \
    "$PYTHON_CORE" --repository "$REPOSITORY_DIR" \
    --launcher "$LAUNCHER_PATH" "$@"
