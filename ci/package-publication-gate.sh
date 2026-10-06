#!/usr/bin/env bash
set -euo pipefail

version="${RELEASE_TAG:?release tag required}"
version="${version#v}"
nginx_version="${NGINX_VERSION:?nginx version required}"
arch="${DEB_ARCH:?package architecture required}"

for type in deb rpm; do
  package="coraza-nginx_${version}_nginx${nginx_version}_${arch}.${type}"
  receipt="verified-${type}.sha256"
  test -s "$package" || { echo "missing tested package: $package" >&2; exit 1; }
  test -s "$receipt" || { echo "missing verification receipt: $receipt" >&2; exit 1; }
  sha256sum "$package" | cmp -s - "$receipt" || {
    echo "verification receipt does not match: $package" >&2
    exit 1
  }
done
