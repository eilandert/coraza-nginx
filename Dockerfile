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
    make \
    curl \
    unzip; \
  rm -rf /var/lib/apt/lists/*

# Omit the argument to use the checksum-verified central pin. Explicit overrides
# retain the existing upstream tarball route.
ARG LIBCORAZA_VERSION
COPY .github/versions.env .github/scripts/fetch-verify.sh /tmp/ci/

RUN set -eux; \
    mkdir -p /tmp/libcoraza-build; \
    if [ "${LIBCORAZA_VERSION+x}" = x ]; then \
      wget "https://github.com/corazawaf/libcoraza/tarball/${LIBCORAZA_VERSION}" -O /tmp/libcoraza.tar.gz; \
      tar -xf /tmp/libcoraza.tar.gz -C /tmp/libcoraza-build; \
    else \
      . /tmp/ci/versions.env; \
      bash /tmp/ci/fetch-verify.sh \
        "https://github.com/corazawaf/libcoraza/archive/refs/tags/${LIBCORAZA_VERSION}.zip" \
        "$LIBCORAZA_SHA256" /tmp/libcoraza.zip; \
      unzip -q /tmp/libcoraza.zip -d /tmp/libcoraza-build; \
    fi; \
    cd /tmp/libcoraza-build/*; \
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
  zlib1g-dev; \
  rm -rf /var/lib/apt/lists/*

COPY . /usr/src/coraza-nginx

# Download sources
RUN set -eux; \
    curl "http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -o - | tar zxC /usr/src -f -;
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
COPY .github/versions.env .github/scripts/fetch-verify.sh /tmp/ci/

RUN (apt-get update -qq && \
    apt-get install -qq --no-install-recommends curl perl && \
    . /tmp/ci/versions.env && \
    bash /tmp/ci/fetch-verify.sh \
        "https://github.com/nginx/nginx-tests/archive/${NGINX_TESTS_REF}.tar.gz" \
        "$NGINX_TESTS_SHA256" tip.tar.gz && \
    tar xzf tip.tar.gz && \
    cd nginx-tests-* && \
    cp /tmp/t/* . && \
    export TEST_NGINX_BINARY=/usr/sbin/nginx && \
    export TEST_NGINX_GLOBALS="load_module \"/usr/lib/nginx/modules/ngx_http_coraza_module.so\"; user root;" && \
    prove -v coraza*.t 2>&1 || true); \
    rm -rf /var/lib/apt/lists/* /tmp/t /tmp/ci /nginx-tests-* /tip.tar.gz

