#!/usr/bin/env bash
# Error controls use the same real image as the passing artifact checks.
set -euo pipefail
if (($# != 2)); then
	echo "usage: $0 linux/amd64|linux/arm64 IMAGE" >&2
	exit 2
fi
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
check="$root/ci/check-image-platform.sh"
scratch=$(mktemp -d)
trap 'rm -rf "${scratch:?}"' EXIT
expect_failure() {
	local name=$1 diagnostic=$2
	shift 2
	if bash "$check" "$@" >"$scratch/output" 2>&1; then
		echo "FAIL $name: unexpected success" >&2
		exit 1
	fi
	if ! grep -F -- "$diagnostic" "$scratch/output"; then
		cat "$scratch/output" >&2
		echo "FAIL $name: expected diagnostic missing" >&2
		exit 1
	fi
	echo "PASS $name"
}
bash "$root/ci/docker-platform-smoke.sh" "$1" "$2"
bash "$check" "$1" "$2" /usr/local/lib/libcoraza.so
expect_failure missing_arguments 'usage:'
expect_failure unsupported_platform 'unsupported platform:' linux/unsupported "$2"
expect_failure absent_artifact 'Could not find the file' "$1" "$2" /missing-elf-artifact
expect_failure malformed_artifact 'Error:' "$1" "$2" /etc/passwd
case "$1" in
linux/amd64) other=linux/arm64 ;;
linux/arm64) other=linux/amd64 ;;
esac
expect_failure wrong_architecture 'FAIL /usr/local/lib/libcoraza.so: expected' \
	"$other" "$2" /usr/local/lib/libcoraza.so
