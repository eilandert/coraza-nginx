#!/usr/bin/env bash
# Exercise the final Docker RUN instruction with harmless stand-ins for its
# external commands. The instruction itself is copied verbatim from Dockerfile.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dockerfile="${F12_DOCKERFILE:-$repo_root/Dockerfile}"
evidence="${F12_EVIDENCE_DIR:-$(mktemp -d)}"
mkdir -p "$evidence"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/fakebin" "$fixture/nginx-tests-fixture"
printf 'NGINX_TESTS_REF=fixture\nNGINX_TESTS_SHA256=fixture\n' >"$fixture/versions.env"
printf '1;\n' >"$fixture/coraza-fixture.t"

cat >"$fixture/fakebin/apt-get" <<'EOF'
#!/bin/sh
if [ "$SCENARIO" = prerequisite ]; then echo 'fixture: prerequisite failed' >&2; exit 41; fi
exit 0
EOF
cat >"$fixture/fakebin/tar" <<'EOF'
#!/bin/sh
if [ "$SCENARIO" = extraction ]; then echo 'fixture: extraction failed' >&2; exit 42; fi
exit 0
EOF
cat >"$fixture/fakebin/prove" <<'EOF'
#!/bin/sh
if [ "$SCENARIO" = test ]; then echo 'fixture: embedded test failed' >&2; exit 43; fi
echo 'fixture: complete embedded test run passed'
exit 0
EOF
cat >"$fixture/fetch-verify.sh" <<'EOF'
#!/bin/sh
case "$SCENARIO" in
  download) echo 'fixture: download failed' >&2; exit 44 ;;
  checksum) echo 'fixture: checksum failed' >&2; exit 45 ;;
esac
exit 0
EOF
chmod +x "$fixture/fakebin/"* "$fixture/fetch-verify.sh"

cat >"$fixture/Dockerfile" <<'EOF'
FROM debian:trixie-slim
ARG SCENARIO=green
ENV SCENARIO=$SCENARIO
ENV PATH=/usr/local/fakebin:$PATH
COPY fakebin/ /usr/local/fakebin/
COPY versions.env fetch-verify.sh /tmp/ci/
COPY coraza-fixture.t /tmp/t/
COPY nginx-tests-fixture/ /nginx-tests-fixture/
EOF
awk '/^RUN apt-get update -qq &&/ { found=1 } found { print } END { if (!found) exit 1 }' \
	"$dockerfile" >>"$fixture/Dockerfile"

for scenario in green prerequisite download checksum extraction test; do
	log="$evidence/$scenario.log"
	case "$scenario" in
	prerequisite) marker='fixture: prerequisite failed' ;;
	download) marker='fixture: download failed' ;;
	checksum) marker='fixture: checksum failed' ;;
	extraction) marker='fixture: extraction failed' ;;
	test) marker='fixture: embedded test failed' ;;
	esac
	if docker build --no-cache --progress=plain --build-arg "SCENARIO=$scenario" \
		-f "$fixture/Dockerfile" "$fixture" >"$log" 2>&1; then
		result=0
	else
		result=$?
	fi
	if [ "$scenario" = green ]; then
		if [ "$result" -ne 0 ] || ! grep -q 'fixture: complete embedded test run passed' "$log"; then
			echo "FAIL: normal embedded test layer did not pass ($log)" >&2
			exit 1
		fi
	elif [ "$result" -eq 0 ] || ! grep -q "$marker" "$log"; then
		echo "FAIL: $scenario did not fail the Docker build ($log)" >&2
		exit 1
	fi
	printf 'PASS: %s Docker layer exit=%s\n' "$scenario" "$result"
done
