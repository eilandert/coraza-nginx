#!/usr/bin/env bash
# Inspect the actual binaries; image platform metadata alone cannot detect a
# build-platform library copied into a target-platform image.
set -euo pipefail
export LC_ALL=C

if (($# < 2)); then
	echo "usage: $0 linux/amd64|linux/arm64 IMAGE [ELF_PATH ...]" >&2
	exit 2
fi
platform=$1
image=$2
shift 2
case "$platform" in
linux/amd64) expected='Advanced Micro Devices X86-64' ;;
linux/arm64) expected='AArch64' ;;
*)
	echo "unsupported platform: $platform" >&2
	exit 2
	;;
esac
if (($# == 0)); then
	set -- /usr/local/lib/libcoraza.so \
		/usr/lib/nginx/modules/ngx_http_coraza_module.so /usr/sbin/nginx
fi
scratch=$(mktemp -d)
container=
cleanup() {
	if [[ -n "$container" ]]; then
		docker rm -f "$container" >/dev/null
	fi
	rm -rf "${scratch:?}"
}
trap cleanup EXIT
# No process runs here; allow mismatched images so the ELF assertion diagnoses them.
container=$(docker create --entrypoint /bin/true "$image")
for path in "$@"; do
	docker cp "$container:$path" "$scratch/artifact" >/dev/null
	machine=$(readelf -h "$scratch/artifact" | sed -n 's/^ *Machine: *//p')
	if [[ "$machine" != "$expected" ]]; then
		echo "FAIL $path: expected $expected for $platform, got $machine" >&2
		exit 1
	fi
	echo "PASS $path: $machine"
done
