#!/usr/bin/env bash
# The caller builds the image first; do not publish host ports for this check.
set -euo pipefail
if (($# != 2)); then
	echo "usage: $0 linux/amd64|linux/arm64 IMAGE" >&2
	exit 2
fi
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
bash "$root/ci/check-image-platform.sh" "$1" "$2"
docker run --rm --platform "$1" --entrypoint sh "$2" -ec '
    nginx -t
    nginx
    trap "nginx -s quit" EXIT
    curl --fail --silent --show-error --retry 20 --retry-connrefused \
        --retry-delay 1 --max-time 10 http://127.0.0.1/ > /tmp/response
    grep -F "Welcome to nginx!" /tmp/response
'
