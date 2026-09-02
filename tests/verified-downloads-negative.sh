#!/usr/bin/env bash
# Mutation controls for the verified-download policy gate.
set -euo pipefail

repo_root=${1:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}
checker="$repo_root/tests/verified-downloads.sh"
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

expect_rejected() {
	local name=$1
	local expected=$2
	if "$checker" "$fixture" >"$fixture/output" 2>&1; then
		printf 'negative control unexpectedly passed: %s\n' "$name" >&2
		exit 1
	fi
	grep -Fq "$expected" "$fixture/output" || {
		printf 'negative control failed for the wrong reason: %s\n' "$name" >&2
		cat "$fixture/output" >&2
		exit 1
	}
	printf 'negative control rejected: %s\n' "$name"
}

reset_fixture() {
	rm -rf "$fixture/Dockerfile" "$fixture/build.sh" "$fixture/.github"
	mkdir -p "$fixture/.github"
	cp "$repo_root/Dockerfile" "$fixture/Dockerfile"
	cp "$repo_root/build.sh" "$fixture/build.sh"
	cp "$repo_root/.github/versions.env" "$fixture/.github/versions.env"
}

reset_fixture
sed -i 's@    bash /usr/src/coraza-nginx/.github/scripts/fetch-verify.sh@    false \&\& bash /usr/src/coraza-nginx/.github/scripts/fetch-verify.sh@' "$fixture/Dockerfile"
expect_rejected 'disabled verified fetch' 'Docker nginx verified fetch is disabled or conditionally chained'

reset_fixture
sed -i 's@/tmp/nginx.tar.gz; \\@/tmp/nginx.tar.gz || true; \\@' "$fixture/Dockerfile"
expect_rejected 'ignored verified fetch failure' 'Docker nginx verified fetch has an unsafe suffix'

reset_fixture
# The mutation must preserve these source-level variable expansions literally.
# shellcheck disable=SC1003,SC2016
sed -i '/fetch-verify.sh.*nginx-${NGINX_VERSION}/a\    curl -o /tmp/nginx.tar.gz "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"; \\' "$fixture/Dockerfile"
expect_rejected 'unverified duplicate writer' 'Docker nginx archive has an unverified or duplicate writer'

reset_fixture
# shellcheck disable=SC1003,SC2016
sed -i '/fetch-verify.sh.*nginx-${NGINX_VERSION}/a\    curl \\\n+      -o /tmp/nginx.tar.gz "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"; \\' "$fixture/Dockerfile"
expect_rejected 'multiline unverified duplicate writer' 'Docker nginx archive has an unverified or duplicate writer'

reset_fixture
# A symlink swaps the archive contents after verification without invoking any
# download command, so the writer census must count "ln" as a writer.
# shellcheck disable=SC1003,SC2016
sed -i '/fetch-verify.sh.*nginx-${NGINX_VERSION}/a\    ln -sf /tmp/other.tar.gz /tmp/nginx.tar.gz; \\' "$fixture/Dockerfile"
expect_rejected 'symlink replacement after verification' 'Docker nginx archive has an unverified or duplicate writer'

reset_fixture
# A plain redirection names no download command at all.
# shellcheck disable=SC1003,SC2016
sed -i '/fetch-verify.sh.*nginx-${NGINX_VERSION}/a\    cat /tmp/other.tar.gz > /tmp/nginx.tar.gz; \\' "$fixture/Dockerfile"
expect_rejected 'redirection replacement after verification' 'Docker nginx archive has an unverified or duplicate writer'

reset_fixture
sed -i 's@tar -xzf /tmp/nginx.tar.gz@tar -xzf /tmp/other.tar.gz@' "$fixture/Dockerfile"
expect_rejected 'extraction detached from verified archive' 'Docker nginx extraction is missing'

printf 'verified download negative controls: ok\n'
