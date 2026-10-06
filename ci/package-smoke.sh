#!/usr/bin/env bash
set -euo pipefail

package_type="${1:?package type required}"
nginx_version="${NGINX_VERSION:?nginx version required}"
package_arch="${PKG_ARCH:?package architecture required}"
package_dir="${GITHUB_WORKSPACE:-/packages}"
shopt -s nullglob
packages=("$package_dir"/coraza-nginx_*_nginx"${nginx_version}"_"${package_arch}"."$package_type")
test "${#packages[@]}" -eq 1
package="${packages[0]}"
tmpdir="$(mktemp -d)"
trap 'nginx -p "$tmpdir/" -c "$tmpdir/nginx.conf" -s stop >/dev/null 2>&1 || true; rm -rf "$tmpdir"' EXIT

if [[ "$package_type" == deb ]]; then
	expected="${nginx_version}-1~noble"
	actual="$(dpkg-deb -f "$package" Depends)"
	[[ ",$actual," == *"nginx (= $expected)"* ]] || {
		echo "missing exact Debian nginx dependency: $actual" >&2
		exit 1
	}
	sudo apt-get update -qq
	sudo apt-get install -y --no-install-recommends nginx curl ca-certificates
	if sudo dpkg -i "$package" 2>&1 | tee "$tmpdir/incompatible.log"; then
		echo 'incompatible Debian nginx was accepted' >&2
		exit 1
	fi
	grep -q 'dependency problems' "$tmpdir/incompatible.log"
	sudo dpkg --purge coraza-nginx
	nginx_deb="nginx_${expected}_${package_arch}.deb"
	curl -fsSL "https://nginx.org/packages/ubuntu/pool/nginx/n/nginx/$nginx_deb" -o "$tmpdir/$nginx_deb"
	sudo apt-get install -y --no-install-recommends "$tmpdir/$nginx_deb"
	sudo apt-get install -y --no-install-recommends "$package"
	[[ "$(dpkg-query -W -f='${Version}' nginx)" == "$expected" ]]
elif [[ "$package_type" == rpm ]]; then
	expected="${nginx_version}-1.el9.ngx"
	actual="$(rpm -qp --requires "$package")"
	grep -Fxq "nginx = 2:$expected" <<<"$actual"
	dnf install -y nginx
	if rpm -i "$package" >"$tmpdir/incompatible.log" 2>&1; then
		echo 'incompatible RPM nginx was accepted' >&2
		exit 1
	fi
	grep -q 'nginx = ' "$tmpdir/incompatible.log"
	dnf remove -y nginx
	rpm_arch="$(rpm --eval '%{_arch}')"
	nginx_rpm="nginx-${expected}.${rpm_arch}.rpm"
	curl -fsSL "https://nginx.org/packages/rhel/9/${rpm_arch}/RPMS/$nginx_rpm" -o "$tmpdir/$nginx_rpm"
	dnf install -y "$tmpdir/$nginx_rpm" "$package"
	[[ "$(rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}' nginx)" == "2:$expected" ]]
else
	echo "unsupported package type: $package_type" >&2
	exit 2
fi

test -f /usr/lib/nginx/modules/ngx_http_coraza_module.so
test -f /usr/local/lib/libcoraza.so
ldconfig -p | grep -q 'libcoraza.so'
mkdir -p "$tmpdir/logs"
cat >"$tmpdir/nginx.conf" <<'EOF'
load_module /usr/lib/nginx/modules/ngx_http_coraza_module.so;
daemon off;
pid nginx.pid;
error_log logs/error.log notice;
events {}
http {
  server {
    listen 127.0.0.1:18081;
    location / { return 200 'coraza-package-smoke'; }
  }
}
EOF
nginx -t -p "$tmpdir/" -c "$tmpdir/nginx.conf"
nginx -p "$tmpdir/" -c "$tmpdir/nginx.conf" &
nginx_pid=$!
for _ in {1..30}; do
	if curl --fail --silent --show-error http://127.0.0.1:18081/ >"$tmpdir/response" 2>/dev/null; then
		break
	fi
	sleep 1
done
if [[ "$(cat "$tmpdir/response" 2>/dev/null)" != coraza-package-smoke ]] ||
	! grep -q 'libcoraza.so loaded via dynlib_open' "$tmpdir/logs/error.log"; then
	cat "$tmpdir/logs/error.log" >&2
	echo 'nginx package smoke did not load libcoraza and serve the benign request' >&2
	exit 1
fi
kill "$nginx_pid"
wait "$nginx_pid" || true
