#!/usr/bin/env bash
#
# Negative control for the UBSan-ownership gate in soak.sh: proves the
# detector goes red on a report naming our src/ and stays green on
# third-party/system-library noise, WITHOUT running a real soak or shipping
# any UB in the connector's C code. Feeds synthetic ubsan log fixtures
# through the exact same detection regex soak.sh uses.
#
# Usage: tools/test-soak-ubsan-gate.sh

set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
SOAK="$SELF/soak.sh"

# Extract the live detection regex straight out of soak.sh so this test
# fails loudly if that line is edited/removed, instead of silently testing
# a stale copy of the pattern.
PATTERN="$(sed -n "s/.*grep -qE '\\([^']*\\)' \"\\\$WORK\"\\/logs\\/ubsan\\*.*/\\1/p" "$SOAK")"
if [ -z "$PATTERN" ]; then
	echo "FAIL: could not locate the UBSan ownership-detection grep in soak.sh (drifted?)"
	exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

check() {
	local name="$1" fixture="$2" want="$3" # want: red|green
	printf '%s' "$fixture" >"$WORK/ubsan.log"
	if grep -qE "$PATTERN" "$WORK/ubsan.log"; then
		got=red
	else
		got=green
	fi
	if [ "$got" != "$want" ]; then
		echo "FAIL: $name: detector went $got, want $want"
		echo "--- fixture ---"
		cat "$WORK/ubsan.log"
		exit 1
	fi
	echo "ok: $name -> $got"
}

# Real report naming our connector source (absolute workspace path, as the
# ASan/UBSan build in asan.yml actually emits).
check "own-src absolute path" \
	"/home/runner/work/coraza-nginx/coraza-nginx/src/ngx_http_coraza_body_filter.c:214:9: runtime error: signed integer overflow
    #0 0x55a1b2 in ngx_http_coraza_body_filter src/ngx_http_coraza_body_filter.c:214" \
	red

# Real report naming our connector source, relative path form.
check "own-src relative path" \
	"src/ngx_http_coraza_utils.c:88:5: runtime error: null pointer passed as argument 2, which is declared to never be null" \
	red

# Third-party/system noise: nginx core init nullability trip (the documented
# benign case) — must NOT flip the gate red.
check "nginx-core noise" \
	"/usr/src/nginx-1.31.4/src/core/ngx_cycle.c:1123:5: runtime error: null pointer passed as argument 2, which is declared to never be null
    #0 0x55a1b2 in ngx_init_cycle src/core/ngx_cycle.c:1123" \
	green

# Third-party/system noise: a libc/PCRE2 frame with no coraza src/ mention.
check "system-library noise" \
	"/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0: runtime error: applying zero offset to null pointer" \
	green

echo "PASS: UBSan ownership gate detector (soak.sh) — red on our src/, green on third-party noise"
