#!/usr/bin/env bash
set -euo pipefail
set -x

NGINX_VERSION=1.18.0
NGINX_SHA256=4c373e7ab5bf91d34a4f11a0c9496561061ba5eee6020db272a17a7228d35f99
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source_archive="$HOME/src/nginx-${NGINX_VERSION}.tar.gz"

mkdir -p "$HOME/src"

bash "$repo_root/.github/scripts/fetch-verify.sh" "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" "$NGINX_SHA256" "$source_archive"
tar -xzf "$source_archive" -C "$HOME/src"

# Pre-reqs:
# diffstat libpcre2-16-0 libpcre2-32-0 libpcre2-dev libpcre2-posix2 quilt
#  geoip-bin libbsd-dev libedit-dev libfontconfig1-dev libfreetype-dev libfreetype6-dev libgd-dev libgeoip-dev libgeoip1
#  libice-dev libice6 libjbig-dev libjpeg-dev libjpeg-turbo8-dev libjpeg8-dev liblzma-dev libncurses-dev libnetaddr-ip-perl
#  libpng-dev libpthread-stubs0-dev libsm-dev libsm6 libtiff-dev libtiffxx5 libvpx-dev libvpx6 libx11-dev libxau-dev libxcb1-dev
#  libxdmcp-dev libxpm-dev libxslt1-dev libxt-dev libxt6 x11-common x11proto-core-dev x11proto-dev xorg-sgml-doctools xtrans-dev

TEST_NGINX_BINARY=/usr/sbin/nginx
TEST_NGINX_GLOBALS="load_module \"/usr/lib/nginx/modules/ngx_http_coraza_module.so\";"
TEST_NGINX_MODULES=/usr/lib/nginx/modules

export TEST_NGINX_BINARY TEST_NGINX_GLOBALS TEST_NGINX_MODULES

CONFARGS=$(nginx -V 2>&1 | sed -n -e 's/^.*arguments: //p');\
    cd ~/src/nginx-$NGINX_VERSION; \
    ./configure --with-compat "${CONFARGS}" --add-dynamic-module=/vagrant/; \
    make modules; \
    sudo mkdir -p /usr/lib/nginx/modules; \
    find objs/*.so -print; \
    sudo cp objs/ngx_*.so /usr/lib/nginx/modules
