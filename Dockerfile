FROM --platform=$BUILDPLATFORM golang@sha256:c7e98cc0fd4dfb71ee7465fee6c9a5f079163307e4bf141b336bb9dae00159a5 as go-builder

# For latest build deps, see https://github.com/nginxinc/docker-nginx/blob/master/mainline/alpine/Dockerfile
RUN set -eux; \
  apt-get update -qq; \
  apt-get install -qq --no-install-recommends \
    autoconf \
    automake \
    libtool \
    gcc \
    bash \
    make

# libcoraza, pinned by commit + sha256.
#
# LIBCORAZA_VERSION is documentation only: it records which release
# LIBCORAZA_COMMIT is the tag target of. The fetch uses the commit, because a
# tag is a mutable ref — it can be force-moved to different contents — whereas a
# commit archive cannot change. (libcoraza publishes no release assets, so a
# signed/immutable upstream asset is not an option here.) Same reasoning and
# same URL form as NGINX_TESTS_REF below and in .github/versions.env.
#
# Bump all three together; refresh the hash with
#   .github/scripts/fetch-verify.sh <url> - <out>
ARG LIBCORAZA_VERSION=v1.1.0
ARG LIBCORAZA_COMMIT=c3d99787cb2613b13107170d1a018eccdf31ba8a
ARG LIBCORAZA_SHA256=5ce260f644c1ceed9be3aee424475895833fe14aec337f675c10a979adfb296f

RUN set -eux; \
    curl -fSL --retry 3 --retry-delay 2 --connect-timeout 30 --max-time 300 \
      -o /tmp/libcoraza.tar.gz \
      "https://github.com/corazawaf/libcoraza/archive/${LIBCORAZA_COMMIT}.tar.gz"; \
    printf '%s  %s\n' "${LIBCORAZA_SHA256}" /tmp/libcoraza.tar.gz > /tmp/libcoraza.sha256; \
    sha256sum -c /tmp/libcoraza.sha256; \
    tar -xf /tmp/libcoraza.tar.gz; \
    cd libcoraza-*; \
    ./build.sh; \
    ./configure; \
    make; \
    cp libcoraza.a /usr/local/lib/; \
    cp libcoraza.so /usr/local/lib/; \
    mkdir -p /usr/local/include/coraza; \
    cp coraza/coraza.h /usr/local/include/coraza/

FROM nginx:stable@sha256:146adea4768b83c607d0bdfa4188464e3da6e0a3ad4475db1d1d8f64f27c29cc as ngx-coraza

COPY --from=go-builder /usr/local/include/coraza /usr/local/include/coraza
COPY --from=go-builder /usr/local/lib/libcoraza.a /usr/local/lib
COPY --from=go-builder /usr/local/lib/libcoraza.so /usr/local/lib

# For latest build deps, see https://github.com/nginxinc/docker-nginx/blob/master/mainline/alpine/Dockerfile
RUN set -eux; \
  apt-get update -qq; \
  apt-get install -qq --no-install-recommends \
  gcc \
  gnupg1 \
  ca-certificates  \
  libc-dev \
  make \
  openssl \
  curl \
  gnupg \
  wget \
  libpcre2-dev \
  zlib1g-dev

COPY . /usr/src/coraza-nginx

# Download sources.
#
# The nginx release tarball is pinned by version AND sha256. NGINX_VERSION comes
# from the digest-pinned nginx:stable base image above, so it is deterministic —
# but an ARG default alone would silently drift if that digest were ever bumped
# without refreshing the hash. NGINX_SOURCE_VERSION therefore restates the
# version the hash belongs to, and the build fails loudly if the base image's
# NGINX_VERSION no longer matches it.
#
# Refresh both together when bumping the base-image digest:
#   docker image inspect <base> --format '{{range .Config.Env}}{{println .}}{{end}}' | grep NGINX_VERSION
#   .github/scripts/fetch-verify.sh https://nginx.org/download/nginx-<v>.tar.gz - out
ARG NGINX_SOURCE_VERSION=1.28.3
ARG NGINX_SOURCE_SHA256=2c96a946bfb0882a21744ed429770a2123ae1828c7c48665092993ddee91a918

RUN set -eux; \
    if [ "$NGINX_VERSION" != "$NGINX_SOURCE_VERSION" ]; then \
      echo "base image nginx $NGINX_VERSION != pinned source $NGINX_SOURCE_VERSION;" \
           "refresh NGINX_SOURCE_VERSION/NGINX_SOURCE_SHA256" >&2; \
      exit 1; \
    fi; \
    curl -fSL --retry 3 --retry-delay 2 --connect-timeout 30 --max-time 300 \
      -o /tmp/nginx.tar.gz \
      "https://nginx.org/download/nginx-${NGINX_SOURCE_VERSION}.tar.gz"; \
    printf '%s  %s\n' "${NGINX_SOURCE_SHA256}" /tmp/nginx.tar.gz > /tmp/nginx.sha256; \
    sha256sum -c /tmp/nginx.sha256; \
    tar zxC /usr/src -f /tmp/nginx.tar.gz; \
    rm -f /tmp/nginx.tar.gz /tmp/nginx.sha256
    # Reuse same cli arguments as the nginx:alpine image used to build

RUN set -eux; \
    CONFARGS=$(nginx -V 2>&1 | sed -n -e 's/^.*arguments: //p');\
    cd /usr/src/nginx-$NGINX_VERSION; \
    ./configure --with-compat "$CONFARGS" --add-dynamic-module=/usr/src/coraza-nginx; \
    make modules; \
    mkdir -p /usr/lib/nginx/modules; \
    find objs/*.so -print; \
    cp objs/ngx_*.so /usr/lib/nginx/modules
    
FROM nginx:stable@sha256:146adea4768b83c607d0bdfa4188464e3da6e0a3ad4475db1d1d8f64f27c29cc

RUN sed -i -e "s|events {|load_module \"/usr/lib/nginx/modules/ngx_http_coraza_module.so\";\n\nevents {|" /etc/nginx/nginx.conf;

COPY ./coraza.conf /etc/nginx/conf.d/coraza.conf
COPY --from=ngx-coraza /usr/lib/nginx/modules/ /usr/lib/nginx/modules/
COPY --from=go-builder /usr/local/lib/libcoraza.so /usr/local/lib

RUN ldconfig -v

COPY ./t /tmp/t

# nginx-tests has no upstream releases, so it is pinned to an immutable commit
# SHA (GitHub source tarballs are byte-stable per commit) + verified sha256,
# rather than the mutable `tip` the previous revision fetched. Keep in sync with
# NGINX_TESTS_REF / NGINX_TESTS_SHA256 in .github/versions.env.
ARG NGINX_TESTS_REF=76bb761cdcaeb6cb024d605c2ef91bf8d8a602d7
ARG NGINX_TESTS_SHA256=d67d4237799cd3c9509f2555336fed65f3ceb3a6266f8caf71842cac14bb40cd

RUN apt-get update -qq && \
    apt-get install -qq --no-install-recommends curl perl && \
    curl -fSL --retry 3 --retry-delay 2 --connect-timeout 30 --max-time 300 \
      -o nginx-tests.tar.gz \
      "https://github.com/nginx/nginx-tests/archive/${NGINX_TESTS_REF}.tar.gz" && \
    printf '%s  %s\n' "${NGINX_TESTS_SHA256}" nginx-tests.tar.gz > nginx-tests.sha256 && \
    sha256sum -c nginx-tests.sha256 && \
    tar xzf nginx-tests.tar.gz && \
    cd nginx-tests-* && \
    cp /tmp/t/* . && \
    export TEST_NGINX_BINARY=/usr/sbin/nginx && \
    export TEST_NGINX_GLOBALS="load_module \"/usr/lib/nginx/modules/ngx_http_coraza_module.so\"; user root;" && \
    prove -v coraza*.t 2>&1 || true

