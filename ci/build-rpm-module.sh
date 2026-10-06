#!/usr/bin/env bash
set -euo pipefail

dnf install -y gcc gcc-c++ make autoconf automake libtool diffutils pcre2-devel zlib-devel openssl-devel unzip tar gzip
export PATH="/opt/go/bin:$PATH"
mkdir -p /build
curl -fsSL "https://github.com/corazawaf/libcoraza/archive/refs/tags/${LIBCORAZA_VERSION}.zip" -o /build/libcoraza.zip
echo "${LIBCORAZA_SHA256}  /build/libcoraza.zip" | sha256sum -c -
unzip -q /build/libcoraza.zip -d /build
curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -o /build/nginx.tar.gz
echo "${NGINX_SHA256}  /build/nginx.tar.gz" | sha256sum -c -
tar -xzf /build/nginx.tar.gz -C /build
cd /build/libcoraza-*
./build.sh
./configure
make -j2
make install
printf '%s\n' /usr/local/lib >/etc/ld.so.conf.d/coraza-build.conf
ldconfig

cd "/build/nginx-${NGINX_VERSION}"
./configure \
	--with-compat \
	--add-dynamic-module=/src/ \
	--with-cc-opt='-g -O2 -fstack-protector-strong -Wformat -Werror=format-security -Wno-unused-function -fPIC -Wdate-time -D_FORTIFY_SOURCE=2' \
	--with-ld-opt='-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -fPIC' \
	--prefix=/etc/nginx \
	--sbin-path=/usr/sbin/nginx \
	--conf-path=/etc/nginx/nginx.conf \
	--http-log-path=/var/log/nginx/access.log \
	--error-log-path=/var/log/nginx/error.log \
	--lock-path=/var/lock/nginx.lock \
	--pid-path=/run/nginx.pid \
	--modules-path=/usr/lib/nginx/modules \
	--http-client-body-temp-path=/var/cache/nginx/client_temp \
	--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
	--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
	--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
	--http-scgi-temp-path=/var/cache/nginx/scgi_temp \
	--with-debug \
	--with-threads \
	--with-http_ssl_module \
	--with-http_realip_module \
	--with-http_auth_request_module \
	--with-http_v2_module \
	--with-http_v3_module \
	--with-http_sub_module
make modules -j2
mkdir -p /src/rpm-output
cp objs/ngx_http_coraza_module.so /src/rpm-output/
cp /usr/local/lib/libcoraza.so /src/rpm-output/
