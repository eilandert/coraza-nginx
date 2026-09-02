#!/usr/bin/env bash
# Purpose: enforce authenticated, checksum-gated nginx source downloads.
# Usage: verified-downloads.sh [repository-root]; --help prints this text.
# Inputs: Dockerfile, build.sh, and .github/versions.env under repository-root.
# Output: one success line, or a precise policy failure on stderr.
# Side effects: none. Dry-run is unnecessary because the check is read-only.
# Limits: this checks source structure and pin shape; builds verify remote bytes.
# Extend: add each new archive's fetch and extraction markers below.
# Source markers intentionally contain literal shell expansions.
# shellcheck disable=SC2016
set -euo pipefail

usage() {
	sed -n '2,8s/^# //p' "${BASH_SOURCE[0]}"
}

case "${1:-}" in
-h | --help)
	usage
	exit 0
	;;
esac

repo_root="${1:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
dockerfile="$repo_root/Dockerfile"
build_script="$repo_root/build.sh"
versions="$repo_root/.github/versions.env"

fail() {
	printf 'verified downloads: %s\n' "$1" >&2
	exit 1
}

for required in "$dockerfile" "$build_script" "$versions"; do
	[[ -f "$required" ]] || fail "missing ${required#"$repo_root"/}"
done

if grep -nE 'http://(nginx\.org/download|hg\.nginx\.org/nginx-tests)' \
	"$dockerfile" "$build_script"; then
	fail 'unencrypted nginx download remains'
fi

if grep -nE '(curl|wget).*[|][[:space:]]*tar' "$dockerfile" "$build_script"; then
	fail 'archive is streamed into tar before verification'
fi

grep -Eq '^ARG NGINX_SOURCE_VERSION=[0-9]+\.[0-9]+\.[0-9]+$' "$dockerfile" ||
	fail 'Docker nginx version pin is missing or malformed'
grep -Eq '^ARG NGINX_SOURCE_SHA256=[0-9a-f]{64}$' "$dockerfile" ||
	fail 'Docker nginx SHA-256 pin is missing or malformed'
grep -Eq '^NGINX_SHA256=[0-9a-f]{64}$' "$build_script" ||
	fail 'build.sh nginx SHA-256 pin is missing or malformed'
grep -Eq '^NGINX_TESTS_REF=[0-9a-f]{40}$' "$versions" ||
	fail 'nginx-tests commit pin is missing or malformed'
grep -Eq '^NGINX_TESTS_SHA256=[0-9a-f]{64}$' "$versions" ||
	fail 'nginx-tests SHA-256 pin is missing or malformed'

line_for() {
	local file=$1
	local needle=$2
	awk -v needle="$needle" 'index($0, needle) && $0 !~ /^[[:space:]]*#/ {
            print NR; found=1; exit
        }
        END { if (!found) exit 1 }' "$file"
}

active_matches() {
	local file=$1
	local needle=$2
	awk -v needle="$needle" 'index($0, needle) && $0 !~ /^[[:space:]]*#/ { count++ }
		END { print count + 0 }' "$file"
}

assert_before() {
	local file=$1
	local fetch_marker=$2
	local extract_marker=$3
	local label=$4
	local fetch_line extract_line fetch_text fetch_prefix fetch_suffix

	[[ $(active_matches "$file" "$fetch_marker") -eq 1 ]] ||
		fail "$label must have exactly one verified fetch"

	fetch_line=$(line_for "$file" "$fetch_marker") ||
		fail "$label verified fetch is missing"
	fetch_text=$(sed -n "${fetch_line}p" "$file")
	fetch_prefix=${fetch_text%%"$fetch_marker"*}
	[[ $fetch_prefix =~ ^[[:space:]]*bash[[:space:]][^\;\&\|\(\)]*$ ]] ||
		fail "$label verified fetch is disabled or conditionally chained"
	fetch_suffix=${fetch_text#*"$fetch_marker"}
	fetch_suffix=${fetch_suffix//[[:space:]]/}
	[[ -z $fetch_suffix || $fetch_suffix == ";\\" ]] ||
		fail "$label verified fetch has an unsafe suffix"
	extract_line=$(line_for "$file" "$extract_marker") ||
		fail "$label extraction is missing"
	((fetch_line < extract_line)) ||
		fail "$label archive is extracted before verification"
}

assert_no_unverified_writer() {
	local file=$1
	local archive=$2
	local label=$3

	awk -v archive="$archive" '
		function inspect(cmdline) {
			if (cmdline ~ /^[[:space:]]*#/ || !index(cmdline, archive)) return
			if (cmdline ~ /(^|[[:space:];])(curl|wget)([[:space:]]|$)/) count++
			if (cmdline ~ /(^|[[:space:];])(cp|mv|dd|tee|ln|install|rsync)([[:space:]]|$)/) count++
			if (cmdline ~ /fetch-verify\.sh"?([[:space:]]|$)/) count++
			# A redirection writes the archive without naming any command
			# above, so "cat other.tar.gz > archive" would otherwise leave
			# fetch-verify.sh as the only counted writer.  inspect() has
			# already established that this command mentions the archive.
			if (index(cmdline, ">" ) && cmdline ~ />>?[[:space:]]*"?[^[:space:]|&;<]*$/) count++
		}
		{
			line = $0
			sub(/\\[[:space:]]*$/, "", line)
			cmdline = cmdline (cmdline == "" ? "" : " ") line
			if ($0 !~ /\\[[:space:]]*$/) {
				parts = split(cmdline, segment, ";")
				for (part = 1; part <= parts; part++) inspect(segment[part])
				cmdline = ""
			}
		}
		END {
			if (cmdline != "") {
				parts = split(cmdline, segment, ";")
				for (part = 1; part <= parts; part++) inspect(segment[part])
			}
			exit count == 1 ? 0 : 1
		}' "$file" ||
		fail "$label archive has an unverified or duplicate writer"
}

docker_nginx_fetch='fetch-verify.sh "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" "$NGINX_SOURCE_SHA256" /tmp/nginx.tar.gz'
docker_tests_fetch='fetch-verify.sh "https://github.com/nginx/nginx-tests/archive/${NGINX_TESTS_REF}.tar.gz" "$NGINX_TESTS_SHA256" /tmp/nginx-tests.tar.gz'
build_nginx_fetch='fetch-verify.sh" "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" "$NGINX_SHA256" "$source_archive"'
build_nginx_extract='tar -xzf "$source_archive"'

assert_before "$dockerfile" "$docker_nginx_fetch" \
	'tar -xzf /tmp/nginx.tar.gz' 'Docker nginx'
assert_no_unverified_writer "$dockerfile" '/tmp/nginx.tar.gz' 'Docker nginx'
assert_before "$dockerfile" "$docker_tests_fetch" \
	'tar -xzf /tmp/nginx-tests.tar.gz' 'Docker nginx-tests'
assert_no_unverified_writer "$dockerfile" '/tmp/nginx-tests.tar.gz' 'Docker nginx-tests'
assert_before "$build_script" "$build_nginx_fetch" \
	"$build_nginx_extract" 'build.sh nginx'
assert_no_unverified_writer "$build_script" '"$source_archive"' 'build.sh nginx'

printf 'verified downloads: ok\n'
