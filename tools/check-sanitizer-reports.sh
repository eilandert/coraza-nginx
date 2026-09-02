#!/usr/bin/env bash

set -euo pipefail

LOG_DIR="${1:?usage: check-sanitizer-reports.sh <log-directory>}"
if [ ! -d "$LOG_DIR" ]; then
    echo "FAIL: sanitizer log directory does not exist: $LOG_DIR" >&2
    exit 2
fi
problems=0

if compgen -G "$LOG_DIR/asan*" >/dev/null; then
    echo "FAIL: ASan report:"
    cat "$LOG_DIR"/asan*
    problems=1
fi

if compgen -G "$LOG_DIR/ubsan*" >/dev/null; then
    echo "FAIL: UBSan report:"
    cat "$LOG_DIR"/ubsan*
    problems=1
fi

exit "$problems"
