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
    unzip

ARG LIBCORAZA_VERSION=v1.7.0
ARG LIBCORAZA_SHA256=c0211b464a14a2bbfdaa0600617316bc908ed0c540dd287514b3f5826b6c6dfc

RUN set -eux; \
    wget "https://github.com/corazawaf/libcoraza/archive/refs/tags/${LIBCORAZA_VERSION}.zip" -O /tmp/libcoraza.zip; \
    echo "${LIBCORAZA_SHA256}  /tmp/libcoraza.zip" > /tmp/libcoraza.sha256; \
    sha256sum -c /tmp/libcoraza.sha256; \
    unzip -q /tmp/libcoraza.zip; \
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
    
FROM nginx:stable@sha256:146adea4768b83c607d0bdfa4188464e3da6e0a3ad4475db1d1d8f64f27c29cc AS runtime

RUN sed -i -e "s|events {|load_module \"/usr/lib/nginx/modules/ngx_http_coraza_module.so\";\n\nevents {|" /etc/nginx/nginx.conf;

COPY ./coraza.conf /etc/nginx/conf.d/coraza.conf
COPY --from=ngx-coraza /usr/lib/nginx/modules/ /usr/lib/nginx/modules/
COPY --from=go-builder /usr/local/lib/libcoraza.so /usr/local/lib

RUN ldconfig -v

FROM runtime AS test

COPY --from=ngx-coraza /usr/src/coraza-nginx/t /usr/src/coraza-nginx/t
COPY --from=ngx-coraza /usr/src/coraza-nginx/src /usr/src/coraza-nginx/src
COPY --from=ngx-coraza /usr/src/coraza-nginx/config /usr/src/coraza-nginx/config
COPY --from=ngx-coraza /usr/src/coraza-nginx/debian/control /usr/src/coraza-nginx/debian/control

ARG NGINX_TESTS_REF=76bb761cdcaeb6cb024d605c2ef91bf8d8a602d7
ARG NGINX_TESTS_SHA256=d67d4237799cd3c9509f2555336fed65f3ceb3a6266f8caf71842cac14bb40cd

WORKDIR /usr/src/coraza-nginx

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends curl perl && \
    curl -fL "https://github.com/nginx/nginx-tests/archive/${NGINX_TESTS_REF}.tar.gz" -o nginx-tests.tar.gz && \
    echo "${NGINX_TESTS_SHA256}  nginx-tests.tar.gz" > nginx-tests.sha256 && \
    sha256sum -c nginx-tests.sha256 && \
    mkdir nginx-tests && \
    tar xzf nginx-tests.tar.gz --strip-components=1 -C nginx-tests && \
    find t -maxdepth 1 -name 'coraza*.t' ! -name 'coraza-docker-build-contract.t' -exec cp {} nginx-tests \;

WORKDIR /usr/src/coraza-nginx/nginx-tests

RUN export TEST_NGINX_BINARY=/usr/sbin/nginx && \
    export TEST_NGINX_GLOBALS="load_module \"/usr/lib/nginx/modules/ngx_http_coraza_module.so\"; user root;" && \
    prove -v coraza*.t && \
    touch /tmp/coraza-tests-passed

FROM runtime

COPY --from=test /tmp/coraza-tests-passed /tmp/coraza-tests-passed
RUN rm /tmp/coraza-tests-passed
