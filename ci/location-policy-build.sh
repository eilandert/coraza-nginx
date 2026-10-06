#!/usr/bin/env bash
# Compile the module and run inert policy/lifecycle contracts with pinned headers.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build=$(mktemp -d)
trap 'rm -rf -- "$build"' EXIT
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../.github/versions.env
source "$root/.github/versions.env"
bash "$root/.github/scripts/fetch-verify.sh" \
	"https://nginx.org/download/nginx-${NGINX_MAINLINE}.tar.gz" \
	"$NGINX_MAINLINE_SHA256" "$build/nginx.tar.gz"
bash "$root/.github/scripts/fetch-verify.sh" \
	"https://github.com/corazawaf/libcoraza/archive/refs/tags/${LIBCORAZA_VERSION}.zip" \
	"$LIBCORAZA_SHA256" "$build/libcoraza.zip"
tar -xzf "$build/nginx.tar.gz" -C "$build"
unzip -q "$build/libcoraza.zip" -d "$build"
mkdir "$build/include" "$build/include/coraza"
(
	cd "$build/libcoraza-${LIBCORAZA_VERSION#v}"
	go tool cgo -exportheader "$build/include/coraza/coraza.h" \
		libcoraza/coraza.go libcoraza/log.go
)
(
	cd "$build/nginx-${NGINX_MAINLINE}"
	# Upstream ddebug.h has an unused static helper when debug is disabled;
	# retain nginx's normal -Werror gate and its production warning set.
	./configure --with-compat --add-dynamic-module="$root" \
		--with-cc-opt="-I$build/include -Wno-unused-function"
	make -j2 modules
	stat -c 'module size=%s mtime=%y path=%n' objs/ngx_http_coraza_module.so
	sha256sum objs/ngx_http_coraza_module.so
)
TEST_NGINX_SOURCE="$build/nginx-${NGINX_MAINLINE}" \
	TEST_LIBCORAZA_INCLUDE="$build/include" \
	prove -v "$root/ci/location-policy-contract.t"
